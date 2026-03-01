import requests

def on_message(message, chat_id, sender_id):
    """
    This function is automatically called when the bot receives a message.
    :param message: The text content of the received message
    :param chat_id: The ID of the chat where the message was sent
    :param sender_id: The ID of the user who sent the message
    """
    
    # Handle the /start command which is sent when a user clicks "Start Bot"
    if message == "/start":
        send_message(chat_id, "Hello! I am a Demo Bot. Type /joke to get a random joke!")
        
    # Example of using the requests library to hit an external API
    elif message == "/joke":
        try:
            response = requests.get("https://official-joke-api.appspot.com/random_joke")
            if response.status_code == 200:
                data = response.json()
                joke = f"{data['setup']}\n\n{data['punchline']}"
                send_message(chat_id, joke)
            else:
                send_message(chat_id, "Sorry, I couldn't reach the joke server right now.")
        except Exception as e:
            send_message(chat_id, f"Error: {str(e)}")
            
    # Default fallback
    else:
        send_message(chat_id, "I only understand the /joke command. Try that!")

# Note: You do not need to call any run() function at the bottom.
# The 4 Messenger Bot Sandbox will automatically inject the `send_message` function 
# and call `on_message` when necessary.