<<<<<<< HEAD
# Lusher Engineering Services - Electronic Parts Catalog

Welcome to the Lusher Engineering Services electronic parts catalog! This is a fully functional Flask-based web application that allows users to:

- 🔍 **Search, Filter, and Sort** parts
- 🏷️ **Tag** parts with custom labels
- ✍️ **Admin** users can **Add**, **Update**, and **Delete** parts
- 🔐 User Authentication with support for role-based UI (user/admin)

## 🛠 Features

| Feature     | User | Admin |
|-------------|------|-------|
| Filter Parts | ✅   | ✅  |
| Sort Parts   | ✅   | ✅  |
| Tag Parts    | ✅   | ✅  |
| Add Parts    | ❌   | ✅  |
| Update Parts | ❌   | ✅  |
| Delete Parts | ❌   | ✅  |

## 🚀 How to Run Locally

### 1. Requirements
- Python 3.9+
- Internet connection (for API access)
- SSH access credentials (already configured)

### 2. Steps

1. Extract the ZIP file.
2. Double click `run_app.bat` (Windows) or run `run_app.sh` on Mac/Linux.
3. Open your browser and navigate to `http://127.0.0.1:5000/`

The app will install dependencies and launch automatically.

---

## 🔐 Login Info

You can register a new account via the **Register** page. Choose **Admin** or **User** when logging in to access role-specific functionality.

---

## 📁 Project Structure

```
├── app.py                 # Main Flask app
├── requirements.txt       # Python dependencies
├── run_app.bat            # One-click startup for Windows
├── templates/             # HTML files (Jinja2 templates)
├── static/                # CSS, JS, Images
├── utils/                 # Helper modules (models, API integration)
```

---

## 🌐 Technologies Used
- Flask
- MySQL (remote)
- SSH Tunneling (for DB security)
- Bootstrap 5
- Flask-Login

---

Made with ❤️ for ECEN 404.
=======
# Project-Status-Reports
ECEN-403-902
Parts Engineering Database UI for Dr. John Lusher - LES.
Weekly project status reports, back-end database operations, front-end UI development, web application and mobile support.
>>>>>>> ad8a5e728d7ea87e0e8d5b340b77eec66fec0173
