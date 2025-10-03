# Notes Application

## Overview

This is a personal notes management web application built with Flask. Users can create accounts, log in, and manage their private notes. The application provides a simple interface for creating, viewing, and organizing text-based notes with titles and content. It's designed as a lightweight, single-user-per-session note-taking tool with secure authentication.

## Recent Changes

**September 30, 2025 (Latest)**: Redesigned dashboard with minimalist style:
- Clean top navigation bar with "Secure Pad" branding and user controls
- "My Notes" header with note count and "+ New Note" button
- Hidden create form that toggles when clicking "+ New Note" button
- Notes displayed as individual cards in list format (not grid)
- Three-dot menu on each note for delete action
- Minimalist dark design matching reference style
- JavaScript-powered toggles for form and dropdown menus
- Fully responsive design for all screen sizes

**September 30, 2025**: Redesigned complete application with dark theme:
- Modern dark theme with black background and teal (#3ECFBA) accent color
- Professional landing page with hero section and feature cards
- Consistent dark theme across all pages (landing, login, signup, dashboard)
- Improved button styles with hover effects and transitions
- Enhanced form inputs with focus states and smooth animations
- Fully responsive design for mobile, tablet, and desktop

**September 30, 2025**: Implemented complete web-based notes management application with:
- User authentication (signup, login, logout) with hashed passwords
- Personalized dashboard for creating, viewing, and deleting notes
- CSRF protection on all POST forms using session-based tokens
- SQLite database with users and notes tables

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Frontend Architecture

**Technology Stack**: The frontend uses server-side rendered HTML templates with Jinja2 templating engine, styled with vanilla CSS.

**Design Pattern**: Traditional multi-page application (MPA) architecture where each user action triggers a full page reload. This approach was chosen for simplicity and reduced JavaScript complexity.

**Styling**: Custom CSS with a modern dark theme featuring black (#000000) background and teal (#3ECFBA) accent colors. The design uses flexbox and CSS Grid for layouts and includes comprehensive responsive design with breakpoints for mobile, tablet, and desktop views.

**User Interface Components**:
- Landing page with hero section featuring large title, subtitle, call-to-action buttons, and feature cards
- Authentication pages (login/signup) with dark-themed centered card layout and subtle animations
- Dashboard with dark header, user info display, and two main sections: note creation form and notes grid
- Flash message system with color-coded alerts for user feedback
- Smooth hover effects and transitions throughout the interface

### Backend Architecture

**Framework**: Flask web framework chosen for its simplicity and minimal boilerplate for small to medium applications.

**Routing Pattern**: Function-based views with decorators for route handling. The application likely includes routes for:
- Authentication (login, signup, logout)
- Dashboard display
- Note creation
- Note management (view, edit, delete)

**Session Management**: Server-side sessions using Flask's built-in session handling with a secret key stored in environment variables. Session data includes user email and CSRF tokens.

**Security Measures**:
- Password hashing using Werkzeug's `generate_password_hash` and `check_password_hash` functions with bcrypt
- CSRF protection implemented via custom token generation and validation on all POST forms (signup, login, create note, delete note)
- Session-based authentication with protected routes using `@login_required` decorator
- Secure secret key management via environment variables (SESSION_SECRET)
- User authorization checks ensuring users can only access and delete their own notes
- Parameterized SQL queries to prevent SQL injection attacks

**Authentication Flow**:
1. User submits credentials via POST request
2. Backend validates CSRF token
3. Password verification using secure hashing comparison
4. Session creation upon successful authentication
5. Redirect to dashboard with user context

### Data Storage

**Database**: SQLite3 chosen for its simplicity, zero-configuration setup, and suitability for single-server deployments. This is ideal for small to medium-scale applications without high concurrency requirements.

**Database Schema**:

*Users Table*:
- `id`: Integer primary key (auto-increment)
- `email`: Unique text field for user identification
- `password`: Hashed password storage

*Notes Table*:
- `id`: Integer primary key (auto-increment)
- `user_id`: Foreign key reference to users table
- `title`: Text field for note title
- `content`: Text field for note body
- `created_at`: Timestamp with default value of current time

**Database Connection Pattern**: Connection-per-request pattern using a `get_db()` helper function that creates a new SQLite connection with Row factory for dictionary-like access to query results.

**Initialization**: Database schema is created via `init_db()` function using SQL CREATE TABLE statements with IF NOT EXISTS clauses for idempotent setup.

**Pros of SQLite approach**:
- No separate database server required
- Simple file-based storage
- Perfect for development and small deployments
- ACID compliance

**Cons**:
- Limited concurrent write operations
- Not suitable for distributed systems
- Scaling requires migration to client-server database

### External Dependencies

**Python Packages**:
- **Flask**: Core web framework for routing, templating, and request handling
- **Werkzeug**: Security utilities (bundled with Flask) for password hashing
- **sqlite3**: Database interface (Python standard library)
- **secrets**: Cryptographically strong random token generation (Python standard library)

**Runtime Dependencies**:
- Python 3.x environment
- File system access for SQLite database file (`notes.db`)
- Environment variable support for configuration (`SESSION_SECRET`)

**No External Services**: This application is fully self-contained with no third-party API integrations, external authentication providers, or cloud services. All functionality runs locally on the server.