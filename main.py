from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
import uuid
import pandas as pd
from datetime import datetime, timedelta


app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")
USERS = "users.csv"
SESSION_TTL = timedelta(10)
session = {}
write_urls = {"/", "/login", "/logout"}

@app.get("/", response_class=HTMLResponse)
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
            session[session_id] = datetime.now()
            response = RedirectResponse(url="/home", status_code=302)
            response.set_cookie(key="session_id", value=session_id)
            return response

    return templates.TemplateResponse("login.html",
                                      {"request": request,
                                       "error": "Неверный логин или пароль"})




