# StackIt – Minimal Q&A Forum Platform

## Overview
StackIt is a minimal question-and-answer platform that supports collaborative learning and structured knowledge sharing. It’s designed to be simple, user-friendly, and focused on the core experience of asking and answering questions within a community.

## User Roles & Permissions
| Role   | Permissions                                                                 |
|--------|----------------------------------------------------------------------------|
| Guest  | View all questions and answers                                             |
| User   | Register, log in, post questions/answers, vote                            |
| Admin  | Moderate content, manage users, send platform-wide messages, download reports |

## Core Features
1. **Ask Question**
   - Users can submit new questions with:
     - **Title:** Short and descriptive
     - **Description:** Written using a rich text editor
     - **Tags:** Multi-select input (e.g., React, JWT)
2. **Rich Text Editor**
   - Supports:
     - Bold, Italic, Strikethrough
     - Numbered lists, Bullet points
     - Emoji insertion
     - Hyperlink insertion (URL)
     - Image upload
     - Text alignment (Left, Center, Right)
3. **Answering Questions**
   - Users can post answers to any question
   - Answers use the same rich text editor
   - Only logged-in users can post answers
4. **Voting & Accepting Answers**
   - Users can upvote or downvote answers
   - Question owners can mark one answer as accepted
5. **Tagging**
   - Questions must include relevant tags
6. **Notification System**
   - Notification icon (bell) in the top navigation bar
   - Users are notified when:
     - Someone answers their question
     - Someone comments on their answer
     - Someone mentions them using @username
   - Icon shows the number of unread notifications
   - Clicking the icon opens a dropdown with recent notifications

## Admin Role
- Reject inappropriate or spammy content
- Ban users who violate platform policies
- Monitor pending, accepted, or cancelled actions
- Send platform-wide messages (e.g., feature updates, downtime alerts)
- Download reports of user activity, feedback logs, and statistics

## Mockup
[View UI Mockup](https://link.excalidraw.com/l/65VNwvy7c4X/8bM86GXnnUN)

## Getting Started
1. Install dependencies: `pip install -r requirements.txt`
2. Run the app: `python run.py`

## Project Structure
- `app/` – Main application code
- `templates/` – HTML templates
- `static/` – CSS, JS, assets
- `migrations/` – Database migrations

## Requirements
- Python 3.8+
- Flask
- Flask-Login
- Flask-SQLAlchemy
- Flask-Migrate
- WTForms
- Flask-WTF
- Flask-Bcrypt
- Flask-CKEditor (for rich text editor)

## License
MIT
