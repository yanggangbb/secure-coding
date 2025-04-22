import sqlite3
import uuid
from flask import Flask, render_template, request, redirect, url_for, session, flash, g, jsonify
from flask_socketio import SocketIO, send
from flask_wtf.csrf import CSRFProtect, generate_csrf
import bcrypt

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
csrf = CSRFProtect(app)
DATABASE = 'market.db'
socketio = SocketIO(app)

# CSRF 보호 설정
app.config['WTF_CSRF_ENABLED'] = True
app.config['WTF_CSRF_SECRET_KEY'] = 'secret!'
app.config['WTF_CSRF_TIME_LIMIT'] = 3600  # 1시간

# CSRF 토큰을 모든 템플릿에 자동으로 포함
@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=generate_csrf())

# 데이터베이스 연결 관리: 요청마다 연결 생성 후 사용, 종료 시 close
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # 결과를 dict처럼 사용하기 위함
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# 테이블 생성 (최초 실행 시에만)
def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        # 사용자 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                bio TEXT,
                cash INTEGER DEFAULT 100000,
                warning_count INTEGER DEFAULT 0,
                is_blocked BOOLEAN DEFAULT 0,
                is_admin BOOLEAN DEFAULT 0
            )
        """)
        # 상품 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS product (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                price TEXT NOT NULL,
                seller_id TEXT NOT NULL,
                sold_status BOOLEAN DEFAULT 0
            )
        """)
        # 거래 내역 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS transactions (
                id TEXT PRIMARY KEY,
                buyer_id TEXT NOT NULL,
                seller_id TEXT NOT NULL,
                product_id TEXT NOT NULL,
                amount INTEGER NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        # 신고 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS report (
                id TEXT PRIMARY KEY,
                reporter_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                reason TEXT NOT NULL
            )
        """)
        # 채팅 로그 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS chat_log (
                id TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                message TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        db.commit()
# 기본 라우트
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

# 관리자 페이지
@app.route('/admin')
def admin():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    cursor = db.cursor()
    
    # 현재 사용자가 관리자인지 확인
    cursor.execute("SELECT is_admin FROM user WHERE id = ?", (session['user_id'],))
    user = cursor.fetchone()
    
    if not user or not user['is_admin']:
        flash('관리자 권한이 필요합니다.')
        return redirect(url_for('dashboard'))
    
    # 모든 사용자 정보 조회
    cursor.execute("SELECT id, username, warning_count, is_blocked, is_admin FROM user")
    users = cursor.fetchall()
    
    # 모든 상품 정보 조회
    cursor.execute("SELECT p.*, u.username as seller_username FROM product p JOIN user u ON p.seller_id = u.id")
    products = cursor.fetchall()
    
    # 채팅 로그 조회
    cursor.execute("""
        SELECT c.*, u.username 
        FROM chat_log c 
        JOIN user u ON c.username = u.username 
        ORDER BY c.timestamp DESC 
        LIMIT 100
        """)
    chat_logs = cursor.fetchall()
    
    return render_template('admin_panel.html', 
                         users=users,
                         products=products,
                         chat_logs=chat_logs)

# 사용자 경고 초기화
@app.route('/admin/reset_warnings/<user_id>', methods=['POST'])
def reset_warnings(user_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    cursor = db.cursor()
    
    # 현재 사용자가 관리자인지 확인
    cursor.execute("SELECT is_admin FROM user WHERE id = ?", (session['user_id'],))
    user = cursor.fetchone()
    
    if not user or not user['is_admin']:
        flash('관리자 권한이 필요합니다.')
        return redirect(url_for('dashboard'))
    
    # 경고 횟수 초기화
    cursor.execute("UPDATE user SET warning_count = 0 WHERE id = ?", (user_id,))
    db.commit()
    
    flash('경고가 초기화되었습니다.')
    return redirect(url_for('admin'))

# 사용자 차단/해제
@app.route('/admin/toggle_block/<user_id>', methods=['POST'])
def toggle_block(user_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    cursor = db.cursor()
    
    # 현재 사용자가 관리자인지 확인
    cursor.execute("SELECT is_admin FROM user WHERE id = ?", (session['user_id'],))
    user = cursor.fetchone()
    
    if not user or not user['is_admin']:
        flash('관리자 권한이 필요합니다.')
        return redirect(url_for('dashboard'))
    
    # 차단 상태 토글
    cursor.execute("UPDATE user SET is_blocked = NOT is_blocked WHERE id = ?", (user_id,))
    db.commit()
    
    flash('사용자 차단 상태가 변경되었습니다.')
    return redirect(url_for('admin'))

# 상품 삭제
@app.route('/admin/delete_product/<product_id>', methods=['POST'])
def delete_product(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    cursor = db.cursor()
    
    # 현재 사용자가 관리자인지 확인
    cursor.execute("SELECT is_admin FROM user WHERE id = ?", (session['user_id'],))
    user = cursor.fetchone()
    
    if not user or not user['is_admin']:
        flash('관리자 권한이 필요합니다.')
        return redirect(url_for('dashboard'))
    
    # 상품 삭제
    cursor.execute("DELETE FROM product WHERE id = ?", (product_id,))
    db.commit()
    
    flash('상품이 삭제되었습니다.')
    return redirect(url_for('admin'))

# 비밀번호 해싱 함수
def hash_password(password):
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password

# 회원가입 시 비밀번호 해싱하여 저장
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        cursor = db.cursor()
        
        # 중복 사용자 체크
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        if cursor.fetchone() is not None:
            flash('이미 존재하는 사용자명입니다.')
            return redirect(url_for('register'))
        
        user_id = str(uuid.uuid4())
        hashed_password = hash_password(password)  # 비밀번호 암호화
        
        # adminroot 계정인 경우 관리자 권한 부여
        is_admin = 1 if username == 'adminroot' else 0
        
        cursor.execute("INSERT INTO user (id, username, password, is_admin) VALUES (?, ?, ?, ?)", 
                       (user_id, username, hashed_password, is_admin))
        db.commit()
        
        if is_admin:
            flash('관리자 계정이 생성되었습니다. 로그인 해주세요.')
        else:
            flash('회원가입이 완료되었습니다. 로그인 해주세요.')
            
        return redirect(url_for('login'))
    return render_template('register.html')

# 로그인 시 해싱된 비밀번호 비교
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        user = cursor.fetchone()
        
        if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
            session['user_id'] = user['id']
            flash('로그인 성공!')
            return redirect(url_for('dashboard'))
        else:
            flash('아이디 또는 비밀번호가 올바르지 않습니다.')
            return redirect(url_for('login'))
    return render_template('login.html')

# 로그아웃
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('로그아웃되었습니다.')
    return redirect(url_for('index'))

# 대시보드: 사용자 정보와 전체 상품 리스트 표시
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    # 현재 사용자 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    # 모든 상품 조회
    cursor.execute("SELECT p.*, u.username as seller_username FROM product p JOIN user u ON p.seller_id = u.id")
    all_products = cursor.fetchall()
    
    # 상품의 특수문자를 원래대로 변환
    processed_products = []
    for product in all_products:
        product_dict = dict(product)
        product_dict['title'] = product_dict['title'].replace('&amp;', '&').replace('&lt;', '<').replace('&gt;', '>').replace('&quot;', '"').replace('&#x27;', "'").replace('&#x2F;', '/')
        product_dict['description'] = product_dict['description'].replace('&amp;', '&').replace('&lt;', '<').replace('&gt;', '>').replace('&quot;', '"').replace('&#x27;', "'").replace('&#x2F;', '/')
        processed_products.append(product_dict)
    
    return render_template('dashboard.html', products=processed_products, user=current_user)

# 프로필 페이지: bio 업데이트 가능
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    if request.method == 'POST':
        bio = request.form.get('bio', '')
        if len(bio) > 100:
            flash('소개글은 100자 이하여야 합니다.')
            return redirect(url_for('profile'))
        cursor.execute("UPDATE user SET bio = ? WHERE id = ?", (bio, session['user_id']))
        db.commit()
        flash('프로필이 업데이트되었습니다.')
        return redirect(url_for('profile'))
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    return render_template('profile.html', user=current_user)

# 상품 등록
@app.route('/product/new', methods=['GET', 'POST'])
def new_product():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    cursor = db.cursor()
    
    # 사용자의 차단 상태 확인
    cursor.execute("SELECT is_blocked FROM user WHERE id = ?", (session['user_id'],))
    user = cursor.fetchone()
    
    if user and user['is_blocked']:
        flash('차단된 사용자는 상품을 등록할 수 없습니다.')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        price = request.form['price']
        
        # 길이 검증
        if len(title) > 20:
            flash('제목은 20자 이하여야 합니다.')
            return redirect(url_for('new_product'))
        if len(description) > 300:
            flash('설명은 300자 이하여야 합니다.')
            return redirect(url_for('new_product'))
        
        # XSS 방지를 위한 특수문자 치환 (데이터베이스 저장 전에 수행)
        title = title.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#x27;').replace('/', '&#x2F;')
        description = description.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#x27;').replace('/', '&#x2F;')
        
        product_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO product (id, title, description, price, seller_id) VALUES (?, ?, ?, ?, ?)",
            (product_id, title, description, price, session['user_id'])
        )
        db.commit()
        flash('상품이 등록되었습니다.')
        return redirect(url_for('dashboard'))
    return render_template('new_product.html')

# 상품 상세보기
@app.route('/product/<product_id>')
def view_product(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT p.*, u.username as seller_username FROM product p JOIN user u ON p.seller_id = u.id WHERE p.id = ?", (product_id,))
    product = cursor.fetchone()
    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))
    
    # 상품의 특수문자를 원래대로 변환
    product_dict = dict(product)
    product_dict['title'] = product_dict['title'].replace('&amp;', '&').replace('&lt;', '<').replace('&gt;', '>').replace('&quot;', '"').replace('&#x27;', "'").replace('&#x2F;', '/')
    product_dict['description'] = product_dict['description'].replace('&amp;', '&').replace('&lt;', '<').replace('&gt;', '>').replace('&quot;', '"').replace('&#x27;', "'").replace('&#x2F;', '/')
    
    # 현재 사용자 정보 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    
    return render_template('view_product.html', product=product_dict, user=current_user)

# 신고하기
@app.route('/report', methods=['GET', 'POST'])
def report():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        target_id = request.form['target_id']
        reason = request.form['reason']
        db = get_db()
        cursor = db.cursor()
        
        # 신고 대상이 사용자인지 확인
        cursor.execute("SELECT * FROM user WHERE id = ?", (target_id,))
        target_user = cursor.fetchone()
        
        if target_user:
            # 경고 횟수 증가
            cursor.execute("UPDATE user SET warning_count = warning_count + 1 WHERE id = ?", (target_id,))
            # 경고 횟수 확인
            cursor.execute("SELECT warning_count FROM user WHERE id = ?", (target_id,))
            warning_count = cursor.fetchone()['warning_count']
            
            # 경고 횟수가 3회 이상이면 계정 차단
            if warning_count >= 3:
                cursor.execute("UPDATE user SET is_blocked = 1 WHERE id = ?", (target_id,))
                flash(f'사용자 {target_user["username"]}의 계정이 차단되었습니다.')
            else:
                flash(f'신고가 접수되었습니다. 현재 경고 횟수: {warning_count}/3')
        else:
            # 상품 신고의 경우
            cursor.execute("SELECT * FROM product WHERE id = ?", (target_id,))
            product = cursor.fetchone()
            if product:
                # 상품의 판매자에게 경고
                cursor.execute("UPDATE user SET warning_count = warning_count + 1 WHERE id = ?", (product['seller_id'],))
                cursor.execute("SELECT warning_count FROM user WHERE id = ?", (product['seller_id'],))
                warning_count = cursor.fetchone()['warning_count']
                
                if warning_count >= 3:
                    cursor.execute("UPDATE user SET is_blocked = 1 WHERE id = ?", (product['seller_id'],))
                    flash(f'상품 판매자의 계정이 차단되었습니다.')
                else:
                    flash(f'상품 신고가 접수되었습니다. 판매자의 현재 경고 횟수: {warning_count}/3')
            else:
                flash('신고 대상을 찾을 수 없습니다.')
        
        report_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO report (id, reporter_id, target_id, reason) VALUES (?, ?, ?, ?)",
            (report_id, session['user_id'], target_id, reason)
        )
        db.commit()
        return redirect(url_for('dashboard'))
    return render_template('report.html')

# 구매하기
@app.route('/purchase/<product_id>', methods=['POST'])
def purchase(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    cursor = db.cursor()
    
    # 구매자의 차단 상태 확인
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    buyer = cursor.fetchone()
    
    if buyer and buyer['is_blocked']:
        flash('차단된 사용자는 상품을 구매할 수 없습니다.')
        return redirect(url_for('view_product', product_id=product_id))
    
    # 상품 정보 조회
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))
    
    # 이미 판매된 상품인지 확인
    if product['sold_status'] == 1:  # 직접 키로 접근
        flash('이미 판매된 상품입니다.')
        return redirect(url_for('view_product', product_id=product_id))
    
    # 판매자 정보 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (product['seller_id'],))
    seller = cursor.fetchone()
    
    price = int(product['price'])
    
    # 구매자와 판매자가 같은 경우
    if buyer['id'] == seller['id']:
        flash('자신의 상품은 구매할 수 없습니다.')
        return redirect(url_for('view_product', product_id=product_id))
    
    # 잔액 확인
    if buyer['cash'] < price:
        flash('잔액이 부족합니다.')
        return redirect(url_for('view_product', product_id=product_id))
    
    try:
        # 구매자 잔액 차감
        cursor.execute("UPDATE user SET cash = cash - ? WHERE id = ?", (price, buyer['id']))
        # 판매자 잔액 증가
        cursor.execute("UPDATE user SET cash = cash + ? WHERE id = ?", (price, seller['id']))
        # 상품 판매 상태 업데이트
        cursor.execute("UPDATE product SET sold_status = 1 WHERE id = ?", (product_id,))
        # 거래 내역 기록
        transaction_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO transactions (id, buyer_id, seller_id, product_id, amount) VALUES (?, ?, ?, ?, ?)",
            (transaction_id, buyer['id'], seller['id'], product_id, price)
        )
        db.commit()
        flash('구매가 완료되었습니다!')
    except Exception as e:
        db.rollback()
        flash('구매 처리 중 오류가 발생했습니다.')
    
    return redirect(url_for('view_product', product_id=product_id))

# 실시간 채팅: 클라이언트가 메시지를 보내면 전체 브로드캐스트
@socketio.on('send_message')
def handle_send_message_event(data):
    data['message_id'] = str(uuid.uuid4())
    
    # 채팅 로그 저장
    db = get_db()
    cursor = db.cursor()
    cursor.execute("""
        INSERT INTO chat_log (id, username, message)
        VALUES (?, ?, ?)
    """, (data['message_id'], data['username'], data['message']))
    db.commit()
    
    send(data, broadcast=True)

# 판매자 프로필 보기
@app.route('/user/<username>')
def view_user_profile(username):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    cursor = db.cursor()
    
    # 사용자 정보 조회
    cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
    user = cursor.fetchone()
    if not user:
        flash('사용자를 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))
    
    # 사용자의 상품 목록 조회
    cursor.execute("SELECT p.*, u.username as seller_username FROM product p JOIN user u ON p.seller_id = u.id WHERE p.seller_id = ? AND p.sold_status = 0", (user['id'],))
    products = cursor.fetchall()
    
    # 상품의 특수문자를 원래대로 변환
    processed_products = []
    for product in products:
        product_dict = dict(product)
        product_dict['title'] = product_dict['title'].replace('&amp;', '&').replace('&lt;', '<').replace('&gt;', '>').replace('&quot;', '"').replace('&#x27;', "'").replace('&#x2F;', '/')
        product_dict['description'] = product_dict['description'].replace('&amp;', '&').replace('&lt;', '<').replace('&gt;', '>').replace('&quot;', '"').replace('&#x27;', "'").replace('&#x2F;', '/')
        processed_products.append(product_dict)
    
    return render_template('user_profile.html', user=user, products=processed_products)

@app.route('/search')
def search():
    query = request.args.get('q', '').strip()
    if not query:
        return jsonify([])
    
    # 사용자 ID로 검색
    user_products = db.execute(
        'SELECT p.*, u.username as seller_username FROM products p '
        'JOIN users u ON p.seller_id = u.id '
        'WHERE u.username LIKE ? AND p.sold_status = 0',
        ('%' + query + '%',)
    ).fetchall()
    
    # 제목으로 검색
    title_products = db.execute(
        'SELECT p.*, u.username as seller_username FROM products p '
        'JOIN users u ON p.seller_id = u.id '
        'WHERE p.title LIKE ? AND p.sold_status = 0',
        ('%' + query + '%',)
    ).fetchall()
    
    # 중복 제거
    all_products = []
    seen_ids = set()
    
    for product in user_products + title_products:
        if product['id'] not in seen_ids:
            seen_ids.add(product['id'])
            all_products.append(dict(product))
    
    return jsonify(all_products)

if __name__ == '__main__':
    init_db()  # 앱 컨텍스트 내에서 테이블 생성
    socketio.run(app, debug=True)
