"""가족 달력 — 실행: streamlit run app.py
같은 배포 주소와 같은 가족 코드로 입장하면 일정과 대화를 공유합니다.
SQLite는 실행 서버에 저장됩니다. 무료 호스팅의 영구 저장은 보장되지 않습니다.
가족 코드는 공유 비밀번호입니다. 별도 본인 인증이나 개인별 권한은 없습니다.
"""
import calendar
import hashlib
import hmac
import html
import json
import os
import secrets
import sqlite3
from datetime import date, datetime, timedelta
from pathlib import Path

import streamlit as st

DB_PATH = Path(os.environ.get("FAMILY_CALENDAR_DB", str(Path(__file__).with_name("family_calendar.sqlite3"))))
COLORS = {"파랑": "#2563eb", "초록": "#15803d", "주황": "#c2410c", "보라": "#7e22ce", "분홍": "#be185d"}

def connect():
    con = sqlite3.connect(str(DB_PATH), timeout=20)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    con.execute("PRAGMA journal_mode=WAL")
    return con

def init_db():
    with connect() as con:
        con.executescript('''
        CREATE TABLE IF NOT EXISTS rooms(id TEXT PRIMARY KEY, salt TEXT NOT NULL, verifier TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS events(
          id INTEGER PRIMARY KEY AUTOINCREMENT, room TEXT NOT NULL REFERENCES rooms(id),
          title TEXT NOT NULL, owner TEXT NOT NULL, start TEXT NOT NULL, end TEXT NOT NULL,
          clock TEXT NOT NULL DEFAULT '', note TEXT NOT NULL DEFAULT '', color TEXT NOT NULL,
          author TEXT NOT NULL, updated TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS event_room ON events(room,start);
        CREATE TABLE IF NOT EXISTS messages(
          id INTEGER PRIMARY KEY AUTOINCREMENT, room TEXT NOT NULL REFERENCES rooms(id),
          author TEXT NOT NULL, body TEXT NOT NULL, created TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS message_room ON messages(room,id);
        ''')

def room_key(code):
    return hashlib.sha256(code.encode("utf-8")).hexdigest()

def verifier(code, salt):
    return hashlib.pbkdf2_hmac("sha256", code.encode(), bytes.fromhex(salt), 200000).hex()

def enter_room(code, create=False):
    key = room_key(code)
    with connect() as con:
        row = con.execute("SELECT * FROM rooms WHERE id=?", (key,)).fetchone()
        if row:
            return key if hmac.compare_digest(row["verifier"], verifier(code, row["salt"])) else None
        if not create:
            return None
        salt = secrets.token_hex(16)
        con.execute("INSERT OR IGNORE INTO rooms VALUES(?,?,?)", (key, salt, verifier(code, salt)))
    return key

def generate_family_code():
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    for _ in range(100):
        code = ''.join(secrets.choice(alphabet) for _ in range(10))
        if not (any(c.isalpha() for c in code) and any(c.isdigit() for c in code)):
            continue
        with connect() as con:
            exists = con.execute("SELECT 1 FROM rooms WHERE id=?", (room_key(code),)).fetchone()
        if not exists:
            return code
    raise ValueError("코드를 만들지 못했어요. 다시 시도해 주세요.")

def toggle_new_room():
    st.session_state["login_code"] = generate_family_code() if st.session_state.get("create_family") else ""

def create_generated_room(code):
    if len(code)!=10 or not all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" for c in code) or not any(c.isalpha() for c in code) or not any(c.isdigit() for c in code):
        raise ValueError("새 가족방 만들기를 해제한 뒤 다시 체크해 주세요.")
    key = room_key(code)
    salt = secrets.token_hex(16)
    try:
        with connect() as con:
            con.execute("INSERT INTO rooms VALUES(?,?,?)",(key,salt,verifier(code,salt)))
    except sqlite3.IntegrityError:
        raise ValueError("이미 사용된 코드예요. 새 가족방 만들기를 해제한 뒤 다시 체크해 주세요.") from None
    return key

def resolve_code(code):
    # 새 코드는 소문자·공백·하이픈 없이 입력해도 입장 가능.
    # 이전 버전에서 직접 만든 코드는 먼저 원래 값으로 확인.
    code = code.strip()
    key = enter_room(code)
    if key:
        return key,code
    raw = ''.join(code.upper().split()).replace('-','')
    if len(raw)==10:
        key = enter_room(raw)
        if key:
            return key,raw
    if len(raw)==12:
        normalized = '-'.join(raw[i:i+4] for i in range(0,12,4))
        key = enter_room(normalized)
        if key:
            return key,normalized
    return None,None

def events_for(room):
    with connect() as con:
        return [dict(r) for r in con.execute("SELECT * FROM events WHERE room=? ORDER BY start,clock,id", (room,))]

def validate_event(title, owner, start, end, clock, note, color):
    title, owner = str(title).strip(), str(owner).strip()
    if not title or len(title)>80 or not owner or len(owner)>30:
        raise ValueError("일정 제목(80자 이내)과 대상(30자 이내)을 입력해 주세요.")
    a, b = date.fromisoformat(str(start)), date.fromisoformat(str(end))
    if b < a:
        raise ValueError("끝나는 날은 시작하는 날보다 빠를 수 없어요.")
    if clock:
        datetime.strptime(str(clock), "%H:%M")
    if len(str(note))>2000 or color not in COLORS:
        raise ValueError("메모는 2,000자 이내로 입력하고 지정된 색을 골라 주세요.")
    return (title, owner, a.isoformat(), b.isoformat(), str(clock), str(note), color)

def save_event(room, author, values, event_id=None):
    checked = validate_event(*values)
    now = datetime.now().isoformat(timespec="seconds")
    with connect() as con:
        if event_id is None:
            con.execute("INSERT INTO events(room,title,owner,start,end,clock,note,color,author,updated) VALUES(?,?,?,?,?,?,?,?,?,?)", (room,*checked,author,now))
        else:
            cur = con.execute("UPDATE events SET title=?,owner=?,start=?,end=?,clock=?,note=?,color=?,author=?,updated=? WHERE id=? AND room=?", (*checked,author,now,event_id,room))
            if not cur.rowcount:
                raise ValueError("이미 삭제된 일정이에요. 새로고침해 주세요.")

def delete_event(room, event_id):
    with connect() as con:
        con.execute("DELETE FROM events WHERE id=? AND room=?", (event_id,room))

def add_message(room, author, body):
    body = body.strip()
    if not body or len(body)>1000:
        raise ValueError("대화는 1~1,000자로 입력해 주세요.")
    with connect() as con:
        con.execute("INSERT INTO messages(room,author,body,created) VALUES(?,?,?,?)", (room,author,body,datetime.now().isoformat(timespec="seconds")))

def backup_room(room):
    with connect() as con:
        messages = [dict(r) for r in con.execute("SELECT author,body,created FROM messages WHERE room=? ORDER BY id", (room,))]
    return json.dumps({"version":1,"events":[{k:v for k,v in e.items() if k not in ("id","room")} for e in events_for(room)], "messages":messages},ensure_ascii=False,indent=2)

def restore_room(room, payload):
    data = json.loads(payload)
    if not isinstance(data,dict) or data.get("version")!=1:
        raise ValueError("이 앱에서 받은 백업 파일이 아니에요.")
    es, ms = data.get("events"), data.get("messages")
    if not isinstance(es,list) or not isinstance(ms,list) or len(es)>5000 or len(ms)>20000:
        raise ValueError("백업 형식이나 크기를 확인해 주세요.")
    ev, msgs = [], []
    for e in es:
        vals = validate_event(*(e[k] for k in ("title","owner","start","end","clock","note","color")))
        author = str(e["author"])
        if not 1<=len(author)<=20:
            raise ValueError("작성자 이름이 올바르지 않아요.")
        updated = datetime.fromisoformat(e["updated"]).isoformat(timespec="seconds")
        ev.append((room,*vals,author,updated))
    for m in ms:
        author, body = str(m["author"]), str(m["body"])
        if not 1<=len(author)<=20 or not 1<=len(body)<=1000:
            raise ValueError("대화 형식이 올바르지 않아요.")
        msgs.append((room,author,body,datetime.fromisoformat(m["created"]).isoformat(timespec="seconds")))
    # 모든 검증이 끝난 뒤 한 트랜잭션으로 복원합니다.
    with connect() as con:
        con.execute("DELETE FROM events WHERE room=?", (room,))
        con.execute("DELETE FROM messages WHERE room=?", (room,))
        con.executemany("INSERT INTO events(room,title,owner,start,end,clock,note,color,author,updated) VALUES(?,?,?,?,?,?,?,?,?,?)",ev)
        con.executemany("INSERT INTO messages(room,author,body,created) VALUES(?,?,?,?)",msgs)

def draw_calendar(year, month, events):
    today = date.today()
    cells = ['<div class="cal">']
    for label in ["월","화","수","목","금","토","일"]:
        cells.append(f'<div class="weekday">{label}</div>')
    for week in calendar.Calendar(0).monthdatescalendar(year,month):
        for day in week:
            matches = [e for e in events if e["start"]<=day.isoformat()<=e["end"]]
            cls = "day" + (" muted" if day.month!=month else "") + (" today" if day==today else "")
            cells.append(f'<div class="{cls}"><b>{day.day}</b>')
            for e in matches[:3]:
                label = html.escape(e["title"])
                cells.append(f'<div class="badge" style="border-left:3px solid {COLORS[e["color"]]}">{label}</div>')
            if len(matches)>3:
                cells.append(f'<small>외 {len(matches)-3}개</small>')
            cells.append('</div>')
    cells.append('</div>')
    st.markdown(''.join(cells),unsafe_allow_html=True)

def event_form(room, name, existing=None):
    e = existing or {}
    with st.form("edit_event" if existing else "new_event",clear_on_submit=not bool(existing)):
        title = st.text_input("일정 제목",value=e.get("title",""),max_chars=80,placeholder="예: 할머니 생신 식사")
        owner = st.text_input("누구의 일정인가요?",value=e.get("owner",name),max_chars=30,help="개인 이름 또는 '가족 전체'라고 적어 주세요.")
        a,b = st.columns(2)
        start = a.date_input("시작하는 날",value=date.fromisoformat(e["start"]) if existing else st.session_state.get("selected_day",date.today()),format="YYYY/MM/DD")
        end = b.date_input("끝나는 날",value=date.fromisoformat(e["end"]) if existing else st.session_state.get("selected_day",date.today()),format="YYYY/MM/DD")
        all_day = st.checkbox("시간 없이 하루 일정",value=not bool(e.get("clock")))
        clock = st.time_input("약속 시간 (하루 일정이면 무시해요)",value=datetime.strptime(e.get("clock") or "09:00","%H:%M").time(),step=300)
        color = st.selectbox("표시 색상",list(COLORS),index=list(COLORS).index(e.get("color","파랑")))
        note = st.text_area("장소와 메모",value=e.get("note",""),max_chars=2000)
        submitted = st.form_submit_button("수정 저장" if existing else "일정 등록",type="primary",use_container_width=True)
    if submitted:
        try:
            save_event(room,name,(title,owner,start,end,"" if all_day else clock.strftime("%H:%M"),note,color), e.get("id"))
            st.session_state["notice"] = "일정을 저장했어요."
            st.rerun()
        except ValueError as ex:
            st.error(str(ex))

@st.fragment(run_every="5s")
def chat_room(room,name):
    st.subheader("💬 가족 이야기방")
    st.caption("화면을 열어 둔 동안 약 5초마다 새 대화를 확인해요. 휴대폰 푸시 알림은 지원하지 않아요.")
    with connect() as con:
        rows = con.execute("SELECT * FROM (SELECT * FROM messages WHERE room=? ORDER BY id DESC LIMIT 150) ORDER BY id", (room,)).fetchall()
    with st.container(height=410):
        if not rows:
            st.info("아직 대화가 없어요. 가족에게 첫 인사를 남겨 보세요!")
        for r in rows:
            with st.chat_message("user" if r["author"]==name else "assistant"):
                st.text(f'{r["author"]} · {r["created"].replace("T"," ")}')
                st.text(r["body"])
    body = st.chat_input("가족에게 이야기해 주세요 (1,000자 이내)",max_chars=1000)
    if body:
        try:
            add_message(room,name,body)
            st.rerun(scope="fragment")
        except ValueError as ex:
            st.error(str(ex))

def main():
    st.set_page_config(page_title="우리 가족 달력",page_icon="🏡",layout="wide")
    st.markdown('''<style>
    .block-container{max-width:1150px;padding-top:1.5rem} .stButton button{min-height:46px}
    .cal{display:grid;grid-template-columns:repeat(7,minmax(0,1fr));gap:4px;margin:12px 0 24px}
    .weekday{text-align:center;font-weight:bold;padding:8px;color:#64748b}
    .day{min-height:115px;border:1px solid #94a3b8;border-radius:10px;padding:7px;overflow:hidden}
    .muted{opacity:.45}.today{border:3px solid #2563eb}.badge{font-size:13px;margin-top:5px;padding-left:4px;overflow-wrap:anywhere;line-height:1.4}
    @media(max-width:600px){.day{min-height:85px;padding:4px}.badge{font-size:10px}.cal{gap:2px}.block-container{padding-left:.6rem;padding-right:.6rem}}
    </style>''',unsafe_allow_html=True)
    init_db()
    st.title("🏡 우리 가족 달력")
    if "room" not in st.session_state:
        st.write("같은 가족 코드로 들어오면 일정과 이야기를 함께 나눌 수 있어요.")
        name = st.text_input("내 이름 또는 별명",max_chars=20,placeholder="예: 엄마, 아빠, 민수")
        create = st.checkbox("새 가족방 만들기 (처음 한 사람만 선택)",key="create_family",on_change=toggle_new_room)
        code = st.text_input("가족 코드",key="login_code",max_chars=100,
                             type="default" if create else "password",disabled=create,
                             help="새 가족방 만들기를 체크하면 영문과 숫자가 섞인 10자리 코드가 자동으로 입력돼요. 다른 가족은 전달받은 코드를 입력하세요.")
        if create:
            st.caption("자동 입력된 코드를 가족에게 알려 주세요. 아래 버튼을 눌러야 가족방이 만들어져요.")
        ok = st.button("가족방 들어가기",type="primary",use_container_width=True)
        st.caption("가족 코드가 입장 비밀번호예요. 가족방에 들어온 사람은 누구나 모든 일정을 수정·삭제할 수 있어요. 이름은 본인 인증이 아니며 같은 별명을 사용할 수도 있어요.")
        st.warning("서버 임시 저장 방식이에요. 재시작·재배포 시 데이터가 사라질 수 있어요. 중요한 기록은 입장 후 ‘백업·안내’에서 내려받아 주세요. 민감한 정보는 적지 마세요.")
        if ok:
            if not name.strip():
                st.error("이름 또는 별명을 입력해 주세요.")
            elif create:
                try:
                    issued_code = code
                    key = create_generated_room(issued_code)
                    st.session_state.update(room=key,name=name.strip(),family_code=issued_code)
                    st.session_state["notice"]="새 가족방을 만들었어요! 아래 ‘가족 코드 확인’에서 코드를 복사해 가족에게 보내 주세요."
                    st.rerun()
                except ValueError as ex:
                    st.error(str(ex))
            elif not code.strip():
                st.error("가족에게 전달받은 코드를 입력해 주세요.")
            else:
                key,matched_code = resolve_code(code)
                if key:
                    st.session_state.update(room=key,name=name.strip(),family_code=matched_code)
                    st.rerun()
                else:
                    st.error("가족방을 찾지 못했어요. 전달받은 코드를 다시 확인해 주세요.")
        return
    room,name = st.session_state["room"],st.session_state["name"]
    st.caption(f"{name} 님, 반가워요! · 가족에게 이 앱 주소와 같은 가족 코드를 알려 주세요.")
    with st.expander("🔑 가족 코드 확인 · 가족 초대"):
        if st.session_state.get("family_code"):
            st.code(st.session_state["family_code"],language=None)
            st.write("위 코드를 복사해서 이 앱 주소와 함께 가족에게 보내 주세요.")
        else:
            st.info("코드를 확인하려면 알고 있는 가족 코드로 다시 입장해 주세요.")
        st.caption("이 코드를 아는 사람은 입장할 수 있어요. 가족끼리만 공유하고, 나가기 전에 따로 보관해 주세요.")
    if st.button("가족방 나가기"): 
        st.session_state.clear()
        st.rerun()
    if msg:=st.session_state.pop("notice",None):
        st.success(msg)
    tab1,tab2,tab3 = st.tabs(["📅 가족 일정","💬 이야기방","💾 백업·안내"])
    with tab1:
        if st.button("🔄 최신 일정 불러오기"):
            st.rerun()
        events = events_for(room)
        today = date.today()
        c1,c2 = st.columns(2)
        year = c1.number_input("연도",min_value=1900,max_value=2200,value=today.year,step=1)
        month = c2.selectbox("월",list(range(1,13)),index=today.month-1,format_func=lambda x:f"{x}월")
        draw_calendar(int(year),month,events)
        st.caption("달력은 한눈에 보는 용도예요. 아래 날짜를 선택하면 자세한 일정과 수정·삭제 버튼이 나와요.")
        day = st.date_input("살펴볼 날짜",value=today,key="selected_day",format="YYYY/MM/DD")
        day_events = [e for e in events if e["start"]<=day.isoformat()<=e["end"]]
        st.subheader(f"{day.month}월 {day.day}일 일정")
        if not day_events:
            st.info("이날은 등록된 일정이 없어요.")
        for e in day_events:
            with st.expander(f'{e["clock"] or "하루 일정"} · {e["title"]} / {e["owner"]}'):
                st.text(f'{e["start"]} ~ {e["end"]}\n대상: {e["owner"]}\n마지막 저장: {e["author"]}')
                if e["note"]:
                    st.text(e["note"])
                if st.button("이 일정 수정하기",key=f'edit_{e["id"]}'):
                    st.session_state["edit_id"]=e["id"]
                checked = st.checkbox("이 일정을 삭제할게요",key=f'confirm_{e["id"]}')
                if st.button("일정 삭제",key=f'delete_{e["id"]}',disabled=not checked):
                    delete_event(room,e["id"])
                    if st.session_state.get("edit_id")==e["id"]:
                        st.session_state.pop("edit_id",None)
                    st.session_state["notice"]="일정을 삭제했어요."
                    st.rerun()
        editing = next((e for e in events if e["id"]==st.session_state.get("edit_id")),None)
        st.subheader("✏️ 일정 수정" if editing else "➕ 새 일정")
        if editing and st.button("수정 취소하고 새 일정 쓰기"):
            st.session_state.pop("edit_id",None)
            st.rerun()
        event_form(room,name,editing)
        with st.expander("앞으로 7일 안에 있는 일정"):
            upcoming = [e for e in events if e["end"]>=today.isoformat() and e["start"]<=(today+timedelta(days=6)).isoformat()]
            if not upcoming:
                st.write("예정된 일정이 없어요.")
            for e in upcoming:
                st.text(f'{e["start"]} ~ {e["end"]} · {e["clock"] or "하루 일정"} · {e["title"]} ({e["owner"]})')
    with tab2:
        chat_room(room,name)
    with tab3:
        st.subheader("가족 기록 보관하기")
        st.warning("무료 호스팅에서는 서버 재시작·재배포 시 일정과 대화가 사라질 수 있어요. 장기 운영에는 외부 데이터베이스 연동이 필요해요.")
        st.download_button("일정과 대화 백업 내려받기",backup_room(room),file_name=f"family_backup_{date.today().isoformat()}.json",mime="application/json")
        st.caption("백업에는 이 가족방의 전체 일정과 대화가 들어 있어요. 가족 코드는 포함되지 않아요. 안전한 곳에 보관하세요.")
        uploaded = st.file_uploader("백업 파일 불러오기",type=["json"])
        confirm = st.checkbox("복원하면 현재 가족방의 일정과 대화가 백업 내용으로 모두 바뀐다는 것을 확인했어요.")
        if st.button("백업으로 복원",disabled=not(uploaded and confirm)):
            try:
                if uploaded.size>10*1024*1024:
                    raise ValueError("10MB 이하의 백업 파일만 복원할 수 있어요.")
                restore_room(room,uploaded.getvalue().decode("utf-8"))
                st.session_state.pop("edit_id",None)
                st.session_state["notice"]="백업을 복원했어요."
                st.rerun()
            except (ValueError,KeyError,TypeError,sqlite3.Error,OverflowError):
                st.error("복원하지 못했어요. 백업 형식과 날짜를 확인해 주세요. 올바르지 않은 파일은 기존 기록을 바꾸지 않아요.")
        st.divider()
        st.write("사용 순서: 한 사람이 ‘새 가족방 만들기’를 체크해 10자리 코드를 자동 입력한 뒤 입장 → 가족에게 앱 주소와 발급된 코드 전달 → 각자 이름과 같은 코드로 입장")
        st.write("달력은 ‘최신 일정 불러오기’로 갱신하고, 대화는 화면이 열린 동안 약 5초 간격으로 갱신해요. 최근 대화 150개를 표시하며 전체 대화는 백업에 포함돼요.")
        st.caption("앱은 실행 서버의 날짜·시간을 사용해요. 해외 서버라면 한국 시간과 차이가 날 수 있어요. 가족 코드를 잊으면 코드 찾기 기능은 없어요.")

if __name__ == "__main__":
    main()
