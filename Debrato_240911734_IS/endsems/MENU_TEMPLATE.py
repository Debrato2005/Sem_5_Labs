"""Run this file. Replace lab_operation() with the lab code your question needs.
The SHA-256 example uses only built-in Python modules. It is not encryption.
"""
import hashlib


def lab_operation():
    # PASTE YOUR LAB FUNCTION HERE. Add its imports at the top of this file.
    message = input('Message: ')
    print('SHA-256:', hashlib.sha256(message.encode()).hexdigest())


def main():
    while True:
        print('\n1. Run lab operation\n0. Exit')
        choice = input('Choice: ').strip()
        if choice == '0':
            return
        if choice == '1':
            try:
                lab_operation()
            except (ValueError, OSError) as error:
                print('Error:', error)
        else:
            print('Invalid choice')


if __name__ == '__main__':
    try:
        main()
    except (EOFError, KeyboardInterrupt):
        print('\nExit')
