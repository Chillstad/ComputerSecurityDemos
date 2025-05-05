import bcrypt

# Simulate user registration
real_password = "MySecret123!"
salt = bcrypt.gensalt()
hashed = bcrypt.hashpw(real_password.encode(), salt)

# Server perspective
print(f"Server only stores: {hashed.decode()}")  # Can't reverse this!

# Simulate login
input_password = "MySecret123!"
print("Login valid?", bcrypt.checkpw(input_password.encode(), hashed))  # True
print("Server knew password?", real_password in hashed.decode())  # False