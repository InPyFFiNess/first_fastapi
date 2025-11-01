from fastapi import FastAPI, Request, Form, Cookie
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from typing import Annotated, Union
import uuid
import pandas as pd
from datetime import datetime, timedelta
import datetime
from starlette.exceptions import HTTPException
from starlette.responses import Response
from functools import wraps
import csv
import hashlib
import os
import asyncio
import uvicorn
import ssl

app = FastAPI()
ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ssl_context.load_cert_chain('security/cert.pem', keyfile='security/key.pem')
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")
USERS = "users.csv"
SESSION_TTL = timedelta(minutes=3)
sessions = {}
white_urls = ["/", "/login", "/logout", "/register"]
LOG_FILE = 'log.csv'    

if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, mode='w', newline='', encoding='utf-8-sig') as file:
        writer = csv.writer(file)
        writer.writerow(['Дата', 'Время', 'Функция'])

def log(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        request: Request = kwargs.get("request") or next((arg for arg in args if isinstance(arg, Request)), None)
        username = request.cookies.get("username") if request else None

        if not username:
            username = "anonymus"
        
        response: Response = func(*args, **kwargs)
        status_code = response.status_code if isinstance(response, Response) else ""

        now = datetime.datetime.now()
        date_str = now.strftime('%Y-%m-%d')
        time_str = now.strftime('%H:%M:%S')
        func_name = func.__name__

        with open(LOG_FILE, mode='a', newline='', encoding='utf-8-sig') as file:
            writer = csv.writer(file)
            writer.writerow([date_str, time_str, func_name, username or "anonymous", status_code])

        return response
    return wrapper

@app.middleware("http")
@log
async def check_session(request: Request, call_next):
    if request.url.path.startswith("/static") or request.url.path in white_urls:
        return await call_next(request)
    
    session_id = request.cookies.get("session_id")
    if not session_id:
        return RedirectResponse(url="/")

    if session_id not in sessions:
        response = RedirectResponse(url="/")
        response.delete_cookie("session_id")
        return response

    created_session = sessions[session_id]
    current_time = datetime.datetime.now()
    if current_time - created_session > SESSION_TTL:
        del sessions[session_id]
        response = RedirectResponse(url="/")
        response.delete_cookie("session_id")
        return response
    
    sessions[session_id] = current_time

    return await call_next(request) 

@app.get("/", response_class=HTMLResponse)
@app.get("/register", response_class=HTMLResponse)
@log
def get_register_page(request:Request):
    return templates.TemplateResponse("register.html", {"request":request})

@app.post("/register")
@log
def register(request: Request,
             username: str = Form(...),
             password: str = Form(...),
             confirm_password: str = Form(...)):
    users = pd.read_csv(USERS, encoding='utf-8-sig')
    if username.strip() in users['user'].str.strip().values:
        return templates.TemplateResponse("register.html",
                                      {"request": request,
                                       "error": "Такой пользователь уже существует"})
    
    if password != confirm_password:
        return templates.TemplateResponse("register.html",
                                      {"request": request,
                                       "error": "Пароли не совпадают"})
    
    copy_password = password.encode()
    salt = username.encode()
    hash_password = hashlib.pbkdf2_hmac('sha256', copy_password, salt, 100)
    new_user = pd.DataFrame([{"user": username.strip(), "password": hash_password, "role": "user"}])
    new_user.to_csv(USERS, mode='a', header=False, index=False)
    return templates.TemplateResponse("login.html",
                                      {"request": request,
                                       "message": "Регистрация успешна. Теперь войдите"})

@app.get("/login", response_class=HTMLResponse)
@log
def get_login_page(request:Request):
    return templates.TemplateResponse("login.html", {"request":request})

@app.get("/home", response_class=HTMLResponse)
@log
def get_home_page(request:Request):
    return templates.TemplateResponse("home.html", {"request":request})

@app.get("/admins", response_class=HTMLResponse)
@log
def get_admin_page(request:Request):
    role = str(request.cookies.get("role"))
    if role == "admin":
        return templates.TemplateResponse("admins.html", {"request":request})
    else:
        return templates.TemplateResponse("403.html", {"request":request})

@app.post("/login")
@log
def login(request: Request,
          username: str = Form(...),
          password: str = Form(...)):
    users = pd.read_csv(USERS, encoding='utf-8-sig')
    user_row = users.loc[users['user'].str.strip() == username]
    if not user_row.empty:
        stored_password = str(user_row['password'].values[0])
        stored_role = str(user_row['role'].values[0])
        copy_password = password.encode()
        salt = username.encode()
        hash_password = hashlib.pbkdf2_hmac('sha256', copy_password, salt, 100)
        if stored_password == str(hash_password):
            session_id = str(uuid.uuid4())
            sessions[session_id] = datetime.datetime.now()
            response = RedirectResponse(url="/home", status_code=302)
            response.set_cookie(key="session_id", value=session_id)
            response.set_cookie(key="role", value=stored_role)
            response.set_cookie(key="username", value=username)
            return response

    return templates.TemplateResponse("login.html",
                                      {"request": request,
                                       "error": "Неверный логин или пароль"})

@app.get("/logout", response_class=HTMLResponse)
@log
def logout(request: Request):
    session_id = request.cookies.get("session_id")

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
@log
def get_404_page(request:Request):
    return templates.TemplateResponse("404.html", {"request":request})

@app.exception_handler(404)
@log
def not_found_page(request: Request, exc):
    session_id = request.cookies.get("session_id")
    if session_id in sessions:
        print("here")
        return RedirectResponse(url="/404")
    else:
        return RedirectResponse(url="/")
    

@app.get("/403", response_class=HTMLResponse)
@log
def get_403_page(request:Request):
    return templates.TemplateResponse("403.html", {"request":request})