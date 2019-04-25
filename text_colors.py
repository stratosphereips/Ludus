def colored(text,color):
    CRED = '\033[91m'
    CEND = '\033[0m'
    CGREEN = '\033[92m'
    CYELLOW = '\033[93m'
    CBLUE = '\033[94m'

    if color == "green":
        return CGREEN + text + CEND
    elif color == "red":
        return CRED + text + CEND
    elif color == "yellow":
        return CYELLOW + text + CEND
    elif color == "blue":
        return CBLUE + text + CEND
    else:
        return text