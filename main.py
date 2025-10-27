from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
import uuid
import pandas as pd
from datetime import datetime, timedelta
from starlette.exceptions import HTTPException
from functools import wraps
import csv
import hashlib
import os

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")
USERS = "users.csv"
SESSION_TTL = timedelta(10)
sessions = {}
write_urls = ["/", "/login", "/logout"]

@app.middleware("http")
async def check_session(request: Request, call_next):
    if request.url.path.startswith("/static") or request.url.path in write_urls:
        return await call_next(request)
    
    session_id = request.cookies.get("session_id")
    if session_id not in sessions:
        return RedirectResponse(url="/")
    
    created_session = sessions[session_id]
    if datetime.now() - created_session > SESSION_TTL:
        del sessions[session_id]
        return RedirectResponse(url="/")

    return await call_next(request)

@app.get("/", response_class=HTMLResponse)
@app.get("/register", response_class=HTMLResponse)
def get_home_page(request:Request):
    return templates.TemplateResponse("register.html", {"request":request})

@app.post("/register")
def register(request: Request,
             username: str = Form(...),
             password: str = Form(...),
             check_password: str = Form(...)):
    users = pd.read_csv(USERS, encoding='utf-8-sig')
    user_row = users.loc[users['user'].str.strip() == username]
    
    if not user_row.empty:
        return templates.TemplateResponse("register.html",
                                      {"request": request,
                                       "error": "Такой логин уже существует"})
    

@app.get("/login", response_class=HTMLResponse)
def get_login_page(request:Request):
    return templates.TemplateResponse("login.html", {"request":request})

@app.get("/home", response_class=HTMLResponse)
def get_home_page(request:Request):
    return templates.TemplateResponse("home.html", {"request":request})

@app.post("/login")
def login(request: Request,
          username: str = Form(...),
          password: str = Form(...)):
    users = pd.read_csv(USERS, encoding='utf-8-sig')
    user_row = users.loc[users['user'].str.strip() == username]

    if not user_row.empty:
        stored_password = str(user_row['password'].values[0])
        if stored_password == password:
            session_id = str(uuid.uuid4())
            sessions[session_id] = datetime.now()
            response = RedirectResponse(url="/home", status_code=302)
            response.set_cookie(key="session_id", value=session_id)
            copy_password = password.encode()
            salt = os.urandom(16)
            dk = hashlib.pbkdf2_hmac('sha256', copy_password, salt, 100)
            return response

    return templates.TemplateResponse("login.html",
                                      {"request": request,
                                       "error": "Неверный логин или пароль"})

@app.get("/logout", response_class=HTMLResponse)
def logout(request: Request):
    session_id = request.cookies.get("session_id")
    print(session_id)

    if session_id in sessions:
        del sessions[session_id]

    response = templates.TemplateResponse("login.html", {
        "request": request,
        "message": "Сессия завершена",
        "url": "/login"
    })
    response.delete_cookie("session_id")
    return response

@app.get("/404", response_class=HTMLResponse)
def get_home_page(request:Request):
    return templates.TemplateResponse("404.html", {"request":request})

@app.exception_handler(404)
def not_found_handler(request: Request, exc):
    session_id = request.cookies.get("session_id")
    if session_id in sessions:
        return RedirectResponse(url="/404")
    else:
        return RedirectResponse(url="/")
    
