from app import create_app, db
from app.models import Tag

def populate_tags():
    tags = [
        "python", "javascript", "java", "c++", "c#", "php", "html", "css", "sql", "ruby",
        "go", "typescript", "swift", "kotlin", "r", "scala", "bash", "shell", "perl", "dart",
        "reactjs", "angular", "vue.js", "django", "flask", "spring", "node.js", "express",
        "mongodb", "mysql", "postgresql", "firebase", "aws", "azure", "docker", "kubernetes",
        "git", "linux", "windows", "macos", "android", "ios", "machine-learning", "data-science",
        "pandas", "numpy", "tensorflow", "pytorch", "algorithm", "oop", "api", "rest", "graphql"
    ]
    app = create_app()
    with app.app_context():
        for tag_name in tags:
            if not Tag.query.filter_by(name=tag_name).first():
                db.session.add(Tag(name=tag_name))
        db.session.commit()
        print("Tags populated.")

if __name__ == "__main__":
    populate_tags()