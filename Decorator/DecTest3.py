def get_message():
    return "Hello there!"
def compose_greet_func():
        return get_message

greet = compose_greet_func()
print greet()