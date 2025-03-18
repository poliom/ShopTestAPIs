from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel, EmailStr, constr
import jwt
import datetime
from typing import List, Dict
from fastapi.security import OAuth2PasswordBearer
import hashlib

app = FastAPI()

# Симулирана база данни
PRODUCTS = []
CARTS = {}

# Конфигурация за токени
SECRET_KEY = "MY_SECRET_KEY"
ALGORITHM = "HS256"

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# 📌 Регистрация на потребители
class RegisterModel(BaseModel):
    username: constr(min_length=3, max_length=20)
    email: EmailStr
    password: constr(min_length=6)

@app.post("/register")
def register(user: RegisterModel):
    # Проверка дали потребителското име съществува
    with open("users.txt", "r") as f:
        for line in f:
            if user.username in line:
                raise HTTPException(status_code=400, detail="Потребителското име вече съществува!")

    # Запазване в users.txt (хеширане на паролата)
    hashed_password = hashlib.sha256(user.password.encode()).hexdigest()
    with open("users.txt", "a") as f:
        f.write(f"{user.username},{user.email},{hashed_password},user\n")

    return {"message": "Регистрацията е успешна!", "status": 200}

# 📌 Модел за логин
class LoginModel(BaseModel):
    username: str
    password: str

@app.post("/login")
def login(user: LoginModel):
    with open("users.txt", "r") as f:
        for line in f:
            saved_username, email, saved_password, role = line.strip().split(",")
            if user.username == saved_username and hashlib.sha256(user.password.encode()).hexdigest() == saved_password:
                token = jwt.encode({"sub": user.username, "role": role, "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)}, SECRET_KEY, algorithm=ALGORITHM)
                return {"token": token}

    raise HTTPException(status_code=401, detail="Грешно потребителско име или парола!")

# 📌 Функция за валидация на токен
def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Токенът е изтекъл!")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Невалиден токен!")

# 📌 Модел за продукт
class ProductModel(BaseModel):
    name: str
    price: float
    quantity: int

@app.post("/add_product")
def add_product(product: ProductModel, user: dict = Depends(get_current_user)):
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Нямате права за добавяне на продукти!")

    PRODUCTS.append(product.dict())
    return {"message": "Продуктът е добавен успешно!"}

@app.get("/products", response_model=List[Dict])
def get_products():
    return PRODUCTS

# 📌 API за кошница
@app.post("/cart/add")
def add_to_cart(product_name: str, quantity: int, user: dict = Depends(get_current_user)):
    if user["username"] not in CARTS:
        CARTS[user["username"]] = []

    # Проверка дали продуктът съществува
    for product in PRODUCTS:
        if product["name"] == product_name and product["quantity"] >= quantity:
            CARTS[user["username"]].append({"name": product_name, "quantity": quantity, "price": product["price"]})
            return {"message": "Продуктът е добавен в кошницата!"}

    raise HTTPException(status_code=404, detail="Продуктът не е наличен!")

@app.get("/cart")
def get_cart(user: dict = Depends(get_current_user)):
    return {"cart": CARTS.get(user["username"], [])}
