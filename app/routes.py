from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app, send_from_directory, jsonify
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from .models import User, Question, Answer, Tag, Notification, Vote, Comment
from . import db, login_manager

main = Blueprint('main', __name__)

def admin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not any(r.name == 'admin' for r in current_user.roles):
            flash('Admin access required.', 'danger')
            return redirect(url_for('main.index'))
        return f(*args, **kwargs)
    return decorated_function

@main.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('main.index'))
        else:
            flash('Invalid username or password.', 'danger')
    return render_template('login.html')

@main.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('main.index'))

@main.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm = request.form.get('confirm')
        if not username or not email or not password or not confirm:
            flash('Please fill in all fields.', 'danger')
        elif password != confirm:
            flash('Passwords do not match.', 'danger')
        elif User.query.filter_by(username=username).first():
            flash('Username already exists.', 'danger')
        elif User.query.filter_by(email=email).first():
            flash('Email already registered.', 'danger')
        else:
            hashed_pw = generate_password_hash(password)
            user = User(username=username, email=email, password=hashed_pw)
            db.session.add(user)
            db.session.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('main.login'))
    return render_template('register.html')

@main.route('/create_admin', methods=['GET', 'POST'])
def create_admin():
    # Allow creation only if no admin exists
    from .models import Role
    admin_role = Role.query.filter_by(name='admin').first()
    any_admin = False
    if admin_role:
        any_admin = any(admin_role in u.roles for u in User.query.all())
    if any_admin:
        flash('Admin already exists. Remove this route for security.', 'danger')
        return redirect(url_for('main.login'))
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        if not username or not email or not password:
            flash('All fields required.', 'danger')
        elif User.query.filter_by(username=username).first():
            flash('Username exists.', 'danger')
        elif User.query.filter_by(email=email).first():
            flash('Email exists.', 'danger')
        else:
            hashed_pw = generate_password_hash(password)
            user = User(username=username, email=email, password=hashed_pw)
            if not admin_role:
                admin_role = Role(name='admin')
                db.session.add(admin_role)
                db.session.commit()
            user.roles.append(admin_role)
            db.session.add(user)
            db.session.commit()
            flash('Admin user created! You can now log in.', 'success')
            return redirect(url_for('main.login'))
    return '''
    <h2>Create Admin User</h2>
    <form method="post">
        <input name="username" placeholder="Username"><br>
        <input name="email" placeholder="Email"><br>
        <input name="password" type="password" placeholder="Password"><br>
        <button type="submit">Create Admin</button>
    </form>
    '''

@main.route('/upload', methods=['POST'])
def upload():
    import os
    from werkzeug.utils import secure_filename
    f = request.files.get('upload')
    if not f:
        return jsonify({'uploaded': False, 'error': {'message': 'No file uploaded'}}), 400
    filename = secure_filename(f.filename)
    ext = os.path.splitext(filename)[1].lower()
    if ext not in ['.jpg', '.jpeg', '.png', '.gif']:
        return jsonify({'uploaded': False, 'error': {'message': 'Invalid file type'}}), 400
    upload_path = os.path.join(current_app.root_path, '..', 'static', 'uploads')
    os.makedirs(upload_path, exist_ok=True)
    save_path = os.path.join(upload_path, filename)
    # Ensure unique filename
    i = 1
    base, ext = os.path.splitext(filename)
    while os.path.exists(save_path):
        filename = f"{base}_{i}{ext}"
        save_path = os.path.join(upload_path, filename)
        i += 1
    f.save(save_path)
    url = url_for('static', filename=f'uploads/{filename}')
    return jsonify({'uploaded': True, 'url': url})

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@main.route('/')
def index():
    questions = Question.query.order_by(Question.created_at.desc()).all()
    return render_template('index.html', questions=questions)

@main.route('/question/<int:question_id>')
def question_detail(question_id):
    question = Question.query.get_or_404(question_id)
    return render_template('question_detail.html', question=question)

@main.route('/ask', methods=['GET', 'POST'])
@login_required
def ask_question():
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        tag_names = request.form.getlist('tags')
        if not title or not description:
            flash('Title and description are required.', 'danger')
            return render_template('ask.html', tags=Tag.query.all())
        if not tag_names:
            flash('Please select at least one tag.', 'danger')
            return render_template('ask.html', tags=Tag.query.all())
        tags = []
        for name in tag_names:
            tag = Tag.query.filter_by(name=name).first()
            if not tag:
                tag = Tag(name=name)
                db.session.add(tag)
            tags.append(tag)
        # Create question
        question = Question(title=title, description=description, author=current_user)
        question.tags = tags
        db.session.add(question)
        db.session.commit()
        flash('Question posted successfully!', 'success')
        return redirect(url_for('main.question_detail', question_id=question.id))
    all_tags = Tag.query.all()
    return render_template('ask.html', tags=all_tags)

@main.route('/answer/<int:question_id>', methods=['POST'])
@login_required
def answer_question(question_id):
    question = Question.query.get_or_404(question_id)
    content = request.form.get('content')
    if not content:
        flash('Answer cannot be empty.', 'danger')
        return redirect(url_for('main.question_detail', question_id=question_id))
    answer = Answer(content=content, author=current_user, question=question)
    db.session.add(answer)
    db.session.commit()

    # Notify question author (unless self-answer)
    if question.author.id != current_user.id:
        notif = Notification(
            user_id=question.author.id,
            message=f"{current_user.username} answered your question.",
            type='answer',
            url=url_for('main.question_detail', question_id=question.id, _external=False),
            related_id=answer.id
        )
        db.session.add(notif)

    # Notify mentioned users (in answer content)
    import re
    mentioned = set(re.findall(r'@([a-zA-Z0-9_]+)', content or ''))
    for username in mentioned:
        user = User.query.filter_by(username=username).first()
        if user and user.id != current_user.id:
            notif = Notification(
                user_id=user.id,
                message=f"{current_user.username} mentioned you in an answer.",
                type='mention',
                url=url_for('main.question_detail', question_id=question.id, _external=False),
                related_id=answer.id
            )
            db.session.add(notif)
    db.session.commit()
    flash('Answer posted successfully!', 'success')
    return redirect(url_for('main.question_detail', question_id=question_id))

@main.route('/vote/<int:answer_id>/<string:action>')
@login_required
def vote_answer(answer_id, action):
    answer = Answer.query.get_or_404(answer_id)
    existing_vote = Vote.query.filter_by(user_id=current_user.id, answer_id=answer_id).first()
    rep_delta = 0
    # Upvote
    if action == 'upvote':
        if existing_vote and existing_vote.value == 1:
            flash('You have already upvoted.', 'info')
            return redirect(url_for('main.question_detail', question_id=answer.question_id))
        if existing_vote:
            # Changing from downvote to upvote
            if answer.user_id != current_user.id:
                answer.author.reputation += 12  # -2 to +10
            existing_vote.value = 1
        else:
            vote = Vote(user_id=current_user.id, answer_id=answer_id, value=1)
            db.session.add(vote)
            if answer.user_id != current_user.id:
                answer.author.reputation += 10
        db.session.commit()
        flash('Upvote recorded.', 'success')
    # Downvote
    elif action == 'downvote':
        if existing_vote and existing_vote.value == -1:
            flash('You have already downvoted.', 'info')
            return redirect(url_for('main.question_detail', question_id=answer.question_id))
        if existing_vote:
            # Changing from upvote to downvote
            if answer.user_id != current_user.id:
                answer.author.reputation -= 12  # +10 to -2
            existing_vote.value = -1
        else:
            vote = Vote(user_id=current_user.id, answer_id=answer_id, value=-1)
            db.session.add(vote)
            if answer.user_id != current_user.id:
                answer.author.reputation -= 2
        db.session.commit()
        flash('Downvote recorded.', 'success')
    else:
        flash('Invalid vote action.', 'danger')
    return redirect(url_for('main.question_detail', question_id=answer.question_id))

@main.route('/vote_question/<int:question_id>/<action>', methods=['POST'])
@login_required
def vote_question(question_id, action):
    question = Question.query.get_or_404(question_id)
    if not hasattr(question, 'votes'):
        flash('Voting not enabled for questions.', 'danger')
        return redirect(url_for('main.question_detail', question_id=question_id))
    existing_vote = Vote.query.filter_by(user_id=current_user.id, answer_id=None, question_id=question_id).first()
    if action == 'upvote':
        if existing_vote and existing_vote.value == 1:
            flash('You have already upvoted.', 'info')
            return redirect(url_for('main.question_detail', question_id=question_id))
        if existing_vote:
            if question.user_id != current_user.id:
                question.author.reputation += 4  # -2 to +2
            existing_vote.value = 1
        else:
            vote = Vote(user_id=current_user.id, answer_id=None, question_id=question_id, value=1)
            db.session.add(vote)
            if question.user_id != current_user.id:
                question.author.reputation += 2
        db.session.commit()
        flash('Upvote recorded.', 'success')
    elif action == 'downvote':
        if existing_vote and existing_vote.value == -1:
            flash('You have already downvoted.', 'info')
            return redirect(url_for('main.question_detail', question_id=question_id))
        if existing_vote:
            if question.user_id != current_user.id:
                question.author.reputation -= 4  # +2 to -2
            existing_vote.value = -1
        else:
            vote = Vote(user_id=current_user.id, answer_id=None, question_id=question_id, value=-1)
            db.session.add(vote)
            if question.user_id != current_user.id:
                question.author.reputation -= 2
        db.session.commit()
        flash('Downvote recorded.', 'success')
    else:
        flash('Invalid vote action.', 'danger')
    return redirect(url_for('main.question_detail', question_id=question_id))

@main.route('/accept_answer/<int:question_id>/<int:answer_id>', methods=['POST'])
@login_required
def accept_answer(question_id, answer_id):
    question = Question.query.get_or_404(question_id)
    if current_user.id != question.user_id:
        flash('Only the question owner can accept an answer.', 'danger')
        return redirect(url_for('main.question_detail', question_id=question_id))
    answer = Answer.query.get_or_404(answer_id)
    if answer.user_id != current_user.id:
        answer.author.reputation += 15
    question.accepted_answer_id = answer_id
    db.session.commit()
    flash('Answer accepted!', 'success')
    return redirect(url_for('main.question_detail', question_id=question_id))

@main.route('/user/<username>')
def user_profile(username):
    user = User.query.filter_by(username=username).first_or_404()
    questions = Question.query.filter_by(user_id=user.id).order_by(Question.created_at.desc()).all()
    answers = Answer.query.filter_by(user_id=user.id).order_by(Answer.created_at.desc()).all()
    comments = Comment.query.filter_by(user_id=user.id).order_by(Comment.created_at.desc()).all()
    return render_template('profile.html', user=user, questions=questions, answers=answers, comments=comments)

@main.route('/user/<username>/edit', methods=['GET', 'POST'])
@login_required
def edit_profile(username):
    user = User.query.filter_by(username=username).first_or_404()
    if user.id != current_user.id:
        flash('You can only edit your own profile.', 'danger')
        return redirect(url_for('main.user_profile', username=username))
    if request.method == 'POST':
        bio = request.form.get('bio', '')
        avatar_url = request.form.get('avatar_url', '')
        user.bio = bio
        user.avatar_url = avatar_url
        db.session.commit()
        flash('Profile updated!', 'success')
        return redirect(url_for('main.user_profile', username=username))
    return render_template('edit_profile.html', user=user)

@main.route('/notifications')
@login_required
def notifications():
    notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.created_at.desc()).all()
    return render_template('notifications.html', notifications=notifications)

@main.route('/notifications/mark_read', methods=['POST'])
@login_required
def mark_notifications_read():
    Notification.query.filter_by(user_id=current_user.id, is_read=False).update({'is_read': True})
    db.session.commit()
    flash('All notifications marked as read.', 'success')
    return redirect(url_for('main.notifications'))

@main.route('/admin')
@admin_required
def admin_panel():
    users = User.query.all()
    questions = Question.query.order_by(Question.created_at.desc()).all()
    answers = Answer.query.order_by(Answer.created_at.desc()).all()
    from .models import Report
    reports = Report.query.all()
    # Dashboard stats
    total = max(len(users) + len(questions) + len(answers) + len(reports), 1)
    stats = {
        'users': len(users),
        'questions': len(questions),
        'answers': len(answers),
        'reports': len(reports),
        'users_percent': int((len(users)/total)*100),
        'questions_percent': int((len(questions)/total)*100),
        'answers_percent': int((len(answers)/total)*100),
        'reports_percent': int((len(reports)/total)*100)
    }
    return render_template('admin.html', users=users, questions=questions, answers=answers, stats=stats)

@main.route('/admin/ban_user/<int:user_id>', methods=['POST'])
@admin_required
def ban_user(user_id):
    user = User.query.get_or_404(user_id)
    user.is_banned = True
    db.session.commit()
    flash(f'User {user.username} banned.', 'success')
    return redirect(url_for('main.admin_panel'))

@main.route('/admin/unban_user/<int:user_id>', methods=['POST'])
@admin_required
def unban_user(user_id):
    user = User.query.get_or_404(user_id)
    user.is_banned = False
    db.session.commit()
    flash(f'User {user.username} unbanned.', 'success')
    return redirect(url_for('main.admin_panel'))

@main.route('/admin/approve_question/<int:question_id>', methods=['POST'])
@admin_required
def approve_question(question_id):
    q = Question.query.get_or_404(question_id)
    q.is_approved = True
    db.session.commit()
    flash('Question approved.', 'success')
    return redirect(url_for('main.admin_panel'))

@main.route('/admin/reject_question/<int:question_id>', methods=['POST'])
@admin_required
def reject_question(question_id):
    q = Question.query.get_or_404(question_id)
    db.session.delete(q)
    db.session.commit()
    flash('Question rejected and deleted.', 'info')
    return redirect(url_for('main.admin_panel'))

@main.route('/admin/approve_answer/<int:answer_id>', methods=['POST'])
@admin_required
def approve_answer(answer_id):
    a = Answer.query.get_or_404(answer_id)
    a.is_approved = True
    db.session.commit()
    flash('Answer approved.', 'success')
    return redirect(url_for('main.admin_panel'))

@main.route('/admin/reject_answer/<int:answer_id>', methods=['POST'])
@admin_required
def reject_answer(answer_id):
    a = Answer.query.get_or_404(answer_id)
    db.session.delete(a)
    db.session.commit()
    flash('Answer rejected and deleted.', 'info')
    return redirect(url_for('main.admin_panel'))

@main.route('/admin/send_message', methods=['POST'])
@admin_required
def send_platform_message():
    msg = request.form.get('message')
    if msg:
        users = User.query.all()
        for user in users:
            notif = Notification(user_id=user.id, message=msg, type='admin', url=url_for('main.index'))
            db.session.add(notif)
        db.session.commit()
        flash('Message sent to all users.', 'success')
    return redirect(url_for('main.admin_panel'))

import csv
from io import StringIO

from .models import Comment, Report

@main.route('/report/question/<int:question_id>', methods=['POST'])
@login_required
def report_question(question_id):
    reason = request.form.get('reason')
    if not reason:
        flash('Please provide a reason for reporting.', 'danger')
        return redirect(url_for('main.question_detail', question_id=question_id))
    report = Report(reporter_id=current_user.id, question_id=question_id, reason=reason)
    db.session.add(report)
    db.session.commit()
    flash('Question reported for review.', 'info')
    return redirect(url_for('main.question_detail', question_id=question_id))

@main.route('/report/answer/<int:answer_id>', methods=['POST'])
@login_required
def report_answer(answer_id):
    reason = request.form.get('reason')
    answer = Answer.query.get_or_404(answer_id)
    if not reason:
        flash('Please provide a reason for reporting.', 'danger')
        return redirect(url_for('main.question_detail', question_id=answer.question_id))
    report = Report(reporter_id=current_user.id, answer_id=answer_id, reason=reason)
    db.session.add(report)
    db.session.commit()
    flash('Answer reported for review.', 'info')
    return redirect(url_for('main.question_detail', question_id=answer.question_id))

@main.route('/report/comment/<int:comment_id>', methods=['POST'])
@login_required
def report_comment(comment_id):
    reason = request.form.get('reason')
    comment = Comment.query.get_or_404(comment_id)
    if not reason:
        flash('Please provide a reason for reporting.', 'danger')
        if comment.question_id:
            return redirect(url_for('main.question_detail', question_id=comment.question_id))
        elif comment.answer_id:
            a = Answer.query.get(comment.answer_id)
            return redirect(url_for('main.question_detail', question_id=a.question_id))
    report = Report(reporter_id=current_user.id, comment_id=comment_id, reason=reason)
    db.session.add(report)
    db.session.commit()
    flash('Comment reported for review.', 'info')
    if comment.question_id:
        return redirect(url_for('main.question_detail', question_id=comment.question_id))
    elif comment.answer_id:
        a = Answer.query.get(comment.answer_id)
        return redirect(url_for('main.question_detail', question_id=a.question_id))

@main.route('/admin/reports')
@admin_required
def admin_reports():
    reports = Report.query.order_by(Report.created_at.desc()).all()
    return render_template('admin_reports.html', reports=reports)

@main.route('/admin/reports/<int:report_id>/review', methods=['POST'])
@admin_required
def review_report(report_id):
    report = Report.query.get_or_404(report_id)
    report.status = 'reviewed'
    db.session.commit()
    flash('Report marked as reviewed.', 'success')
    return redirect(url_for('main.admin_reports'))

@main.route('/admin/reports/<int:report_id>/dismiss', methods=['POST'])
@admin_required
def dismiss_report(report_id):
    report = Report.query.get_or_404(report_id)
    report.status = 'dismissed'
    db.session.commit()
    flash('Report dismissed.', 'info')
    return redirect(url_for('main.admin_reports'))

@main.route('/comment/question/<int:question_id>', methods=['POST'])
@login_required
def comment_on_question(question_id):
    content = request.form.get('comment')
    if not content:
        flash('Comment cannot be empty.', 'danger')
        return redirect(url_for('main.question_detail', question_id=question_id))
    comment = Comment(content=content, user_id=current_user.id, question_id=question_id)
    db.session.add(comment)
    db.session.commit()
    # Notify question owner
    q = Question.query.get(question_id)
    if q and q.author.id != current_user.id:
        notif = Notification(user_id=q.author.id, message=f"{current_user.username} commented on your question.", type='comment', url=url_for('main.question_detail', question_id=question_id))
        db.session.add(notif)
        db.session.commit()
    flash('Comment posted.', 'success')
    return redirect(url_for('main.question_detail', question_id=question_id))

@main.route('/comment/answer/<int:answer_id>', methods=['POST'])
@login_required
def comment_on_answer(answer_id):
    content = request.form.get('comment')
    if not content:
        flash('Comment cannot be empty.', 'danger')
        a = Answer.query.get(answer_id)
        return redirect(url_for('main.question_detail', question_id=a.question_id))
    a = Answer.query.get_or_404(answer_id)
    comment = Comment(content=content, user_id=current_user.id, answer_id=answer_id)
    db.session.add(comment)
    db.session.commit()
    # Notify answer owner
    if a.author.id != current_user.id:
        notif = Notification(user_id=a.author.id, message=f"{current_user.username} commented on your answer.", type='comment', url=url_for('main.question_detail', question_id=a.question_id))
        db.session.add(notif)
        db.session.commit()
    flash('Comment posted.', 'success')
    return redirect(url_for('main.question_detail', question_id=a.question_id))

@main.route('/comment/delete/<int:comment_id>', methods=['POST'])
@login_required
def delete_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    is_admin = any(role.name == 'admin' for role in current_user.roles)
    if comment.user_id != current_user.id and not is_admin:
        flash('You do not have permission to delete this comment.', 'danger')
        if comment.question_id:
            return redirect(url_for('main.question_detail', question_id=comment.question_id))
        elif comment.answer_id:
            a = Answer.query.get(comment.answer_id)
            return redirect(url_for('main.question_detail', question_id=a.question_id))
    comment.is_deleted = True
    db.session.commit()
    flash('Comment deleted.', 'info')
    if comment.question_id:
        return redirect(url_for('main.question_detail', question_id=comment.question_id))
    elif comment.answer_id:
        a = Answer.query.get(comment.answer_id)
        return redirect(url_for('main.question_detail', question_id=a.question_id))

@main.route('/admin/download_report/<string:report_type>')
@admin_required
def download_report(report_type):
    si = StringIO()
    cw = csv.writer(si)
    if report_type == 'users':
        cw.writerow(['id', 'username', 'email', 'is_banned'])
        for u in User.query.all():
            cw.writerow([u.id, u.username, u.email, u.is_banned])
        filename = 'users_report.csv'
    elif report_type == 'questions':
        cw.writerow(['id', 'title', 'author', 'created_at', 'is_approved'])
        for q in Question.query.all():
            cw.writerow([q.id, q.title, q.author.username, q.created_at, q.is_approved])
        filename = 'questions_report.csv'
    elif report_type == 'answers':
        cw.writerow(['id', 'question_id', 'author', 'created_at', 'is_approved'])
        for a in Answer.query.all():
            cw.writerow([a.id, a.question_id, a.author.username, a.created_at, a.is_approved])
        filename = 'answers_report.csv'
    else:
        flash('Invalid report type.', 'danger')
        return redirect(url_for('main.admin_panel'))
    output = si.getvalue()
    return current_app.response_class(
        output,
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment;filename={filename}'}
    )
