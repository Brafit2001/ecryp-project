import unittest
import subprocess
import os
import json
import signal
from ownHmac import hmac_verify_password, extract_password
from symetricEncrypt import decrypt_password


# We create a class for our tests, inheriting from TestCase
class MyTests(unittest.TestCase):

    # We define test methods, which must start with "test_".
    def test_1_option_2_sign_up1(self):
        """Check that it has been registered correctly"""
        # Run the program and capture the output
        process = subprocess.Popen(['python', 'main.py'], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   universal_newlines=True, stdin=subprocess.PIPE)

        # Send option to the program
        option = '2\n'  # Desired option
        process.stdin.write(option)
        process.stdin.flush()

        # Capture username and password
        username = 'test'  # Desired username
        password = '1'  # Desired password

        # Send username and password to the program
        process.stdin.write(username + '\n')
        process.stdin.flush()
        process.stdin.write(password + '\n')
        process.stdin.flush()

        # Get the output and error output
        output, _ = process.communicate()

        process.send_signal(signal.SIGINT)

        # Wait for the program to finish
        process.wait()

        # Check that there was an error when logging in.
        result = ""
        expected_text = "User successfully registered"  # Expected text based on the last line of output
        lines = output.strip().split('\n')
        for line in lines:
            if line == expected_text:
                result = line

        # Compare the last line with the expected text
        self.assertEqual(result, expected_text)

        # Check if the .pem files exists
        pub_pem_file = f'./RSA_keys/PUB_{username}.pem'  # Expected .pem file name
        prk_pem_file = f'./RSA_keys/PRK_{username}.pem'  # Expected .pem file name
        self.assertTrue(os.path.exists(pub_pem_file))
        self.assertTrue(os.path.exists(prk_pem_file))

        # Check if JSONS contain the user
        app_json = "./JSONS/app_users.json"

        with open(app_json) as file:
            data = json.load(file)
            self.assertTrue(data[username.upper()])

        # Check that the hmac key is correct
        key, salt = extract_password(data[username.upper()])
        self.assertTrue(hmac_verify_password(password, salt, key))

    def test_2_option_2_sign_up2(self):
        """Create another user to be able to share passwords"""
        # Run the program and capture the output
        process = subprocess.Popen(['python', 'main.py'], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   universal_newlines=True, stdin=subprocess.PIPE)

        # Send option to the program
        option = '2\n'  # Desired option
        process.stdin.write(option)
        process.stdin.flush()

        # Capture username and password
        username = 'test2'  # Desired username
        password = '1'  # Desired password

        # Send username and password to the program
        process.stdin.write(username + '\n')
        process.stdin.flush()
        process.stdin.write(password + '\n')
        process.stdin.flush()

        # Get the output and error output
        output, _ = process.communicate()

        process.send_signal(signal.SIGINT)

        # Wait for the program to finish
        process.wait()

        # Check that there was an error when logging in.
        result = ""
        expected_text = "User successfully registered"  # Expected text based on the last line of output
        lines = output.strip().split('\n')
        for line in lines:
            if line == expected_text:
                result = line

        # Compare the last line with the expected text
        self.assertEqual(result, expected_text)

        # Check if the .pem files exists
        pub_pem_file = f'./RSA_keys/PUB_{username}.pem'  # Expected .pem file name
        prk_pem_file = f'./RSA_keys/PRK_{username}.pem'  # Expected .pem file name
        self.assertTrue(os.path.exists(pub_pem_file))
        self.assertTrue(os.path.exists(prk_pem_file))

        # Check if JSONS contain the user
        app_json = "./JSONS/app_users.json"

        with open(app_json) as file:
            data = json.load(file)
            self.assertTrue(data[username.upper()])

        # Check that the hmac key is correct
        key, salt = extract_password(data[username.upper()])
        self.assertTrue(hmac_verify_password(password, salt, key))

    def test_3_option_1_invalid_credentials(self):
        """Check that you have tried to log in with a user that exists but with the wrong password."""
        # Run the program and capture the output
        process = subprocess.Popen(['python', 'main.py'], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   universal_newlines=True, stdin=subprocess.PIPE)
        # Send option to the program
        option = '1\n'  # Desired option
        process.stdin.write(option)
        process.stdin.flush()

        # Capture username and password
        username = 'test\n'  # Desired username
        password = '2\n'  # Desired password

        # Send username and password to the program
        process.stdin.write(username)
        process.stdin.flush()
        process.stdin.write(password)
        process.stdin.flush()

        # Get the output and error output
        output, _ = process.communicate()

        # Check that there was an error when logging in.
        result = ""
        expected_text = "Error - Invalid credentials, please try again"  # Expected text based on the last line of output
        lines = output.strip().split('\n')

        for line in lines:
            if line == expected_text:
                result = line

        process.terminate()
        # Compare the last line with the expected text
        self.assertEqual(result, expected_text)

    def test_4_option_1_user_does_not_exist(self):
        """Check that you have tried to log in with a user that not exist"""
        # Run the program and capture the output
        process = subprocess.Popen(['python', 'main.py'], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   universal_newlines=True, stdin=subprocess.PIPE)

        # Send option to the program
        option = '1\n'  # Desired option
        process.stdin.write(option)
        process.stdin.flush()

        # Capture username and password
        username = 'unknown\n'  # Desired username
        password = 'x\n'  # Desired password

        # Send username and password to the program
        process.stdin.write(username)
        process.stdin.flush()
        process.stdin.write(password)
        process.stdin.flush()

        # Get the output and error output
        output, _ = process.communicate()

        process.send_signal(signal.SIGINT)
        process.wait()

        # Check that there was an error when logging in.
        result = ""
        expected_text = "Error - User not registered!"  # Expected text based on the last line of output
        lines = output.strip().split('\n')
        for line in lines:
            if line == expected_text:
                result = line

        # Compare the last line with the expected text
        self.assertEqual(result, expected_text)

    def test_5_option_logged_add_password(self):
        """Check that the password has been saved correctly."""
        # Run the program and capture the output
        process = subprocess.Popen(['python', 'main.py'], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   universal_newlines=True, stdin=subprocess.PIPE)

        # Send option to the program
        option = '1\n'  # Desired option
        process.stdin.write(option)
        process.stdin.flush()

        # Capture username and password
        username = 'test'  # Desired username
        password = '1'  # Desired password

        # Send username and password to the program
        process.stdin.write(username + '\n')
        process.stdin.flush()
        process.stdin.write(password + '\n')
        process.stdin.flush()

        option2 = "2\n"
        process.stdin.write(option2)
        process.stdin.flush()

        site = "Netflix"
        username2 = "test"
        password2 = "1"
        process.stdin.write(site + '\n')
        process.stdin.flush()
        process.stdin.write(username2 + '\n')
        process.stdin.flush()
        process.stdin.write(password2 + '\n')
        process.stdin.flush()
        process.stdin.write("\n")
        process.stdin.flush()

        # Get the output and error output
        output, _ = process.communicate()

        process.send_signal(signal.SIGINT)

        # Wait for the program to finish
        process.wait()

        # Check if there has been an error
        result = ""
        expected_text = "Password saved correctly"  # Expected text based on the last line of output
        lines = output.strip().split('\n')
        for line in lines:
            if line == expected_text:
                result = line

        # Compare the last line with the expected text
        self.assertEqual(result, expected_text)

        # Take the key and the user's salt
        app_json = "./JSONS/app_users.json"

        with open(app_json) as file:
            data = json.load(file)
            self.assertTrue(data[username.upper()])

        key, salt = extract_password(data[username.upper()])

        # Check if JSONS contain the site
        user_external_acc = "./JSONS/users_external_accounts.json"

        with open(user_external_acc) as file:
            data = json.load(file)
            site_info = data[username.upper()][site.upper()]
            self.assertTrue(site_info)

        # Decrypt the message.
        message = decrypt_password(site_info[0], site_info[1], key)
        user_result = message.split(',')[0].split(':')[1]
        password_result = message.split(',')[1].split(':')[1]

        # Check that the username and password match those entered on the keyboard.
        self.assertEqual(user_result, username2)
        self.assertEqual(password_result, password2)

    def test_6_option_logged_see_your_passwords(self):
        """Check that it prints the passwords correctly."""
        # Run the program and capture the output
        process = subprocess.Popen(['python', 'main.py'], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   universal_newlines=True, stdin=subprocess.PIPE)

        # Send option to the program
        option = '1\n'  # Desired option
        process.stdin.write(option)
        process.stdin.flush()

        # Capture username and password
        username = 'test'  # Desired username
        password = '1'  # Desired password

        # Send username and password to the program
        process.stdin.write(username + '\n')
        process.stdin.flush()
        process.stdin.write(password + '\n')
        process.stdin.flush()

        option2 = "1\n"
        process.stdin.write(option2)
        process.stdin.flush()

        site = "Netflix"
        username2 = "test"
        password2 = "1"
        # Get the output and error output
        output, _ = process.communicate()

        process.send_signal(signal.SIGINT)

        # Wait for the program to finish
        process.wait()

        # Check that the site, username and password are printed.
        lines = output.strip().split('\n')
        counter = 0
        for line in lines:
            if site.upper() in line:
                counter += 1
            if f"User:{username2}" in line:
                counter += 1
            if f"Password:{password2}" in line:
                counter += 1

        self.assertEqual(counter, 3)

    def test_7_option_logged_share_password(self):
        """Check that the password is shared correctly"""
        # Run the program and capture the output
        process = subprocess.Popen(['python', 'main.py'], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   universal_newlines=True, stdin=subprocess.PIPE)

        # Send option to the program
        option = '1\n'  # Desired option
        process.stdin.write(option)
        process.stdin.flush()

        # Capture username and password
        username = 'test'  # Desired username
        password = '1'  # Desired password

        # Send username and password to the program
        process.stdin.write(username + '\n')
        process.stdin.flush()
        process.stdin.write(password + '\n')
        process.stdin.flush()

        option2 = "4\n"
        process.stdin.write(option2)
        process.stdin.flush()

        shared_site = "Netflix"
        shared_user = "test2"
        process.stdin.write(shared_user + '\n')
        process.stdin.flush()
        process.stdin.write(shared_site + '\n')
        process.stdin.flush()
        process.stdin.write("\n")
        process.stdin.flush()

        # Get the output and error output
        output, _ = process.communicate()

        process.send_signal(signal.SIGINT)

        # Wait for the program to finish
        process.wait()

        # Check that there was an error when logging in.
        result = ""
        expected_text = "Password shared correctly"  # Expected text based on the last line of output
        lines = output.strip().split('\n')
        for line in lines:
            if line == expected_text:
                result = line
        self.assertEqual(result, expected_text)

    def test_8_option_logged_show_passwords_shared_with_others(self):
        """Check that the sites with which I have shared a password are displayed."""
        # Run the program and capture the output
        process = subprocess.Popen(['python', 'main.py'], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   universal_newlines=True, stdin=subprocess.PIPE)

        # Send option to the program
        option = '1\n'  # Desired option
        process.stdin.write(option)
        process.stdin.flush()

        # Capture username and password
        username = 'test'  # Desired username
        password = '1'  # Desired password

        # Send username and password to the program
        process.stdin.write(username + '\n')
        process.stdin.flush()
        process.stdin.write(password + '\n')
        process.stdin.flush()

        option2 = "6\n"
        process.stdin.write(option2)
        process.stdin.flush()

        shared_site = "Netflix"
        process.stdin.write(shared_site + '\n')
        process.stdin.flush()
        process.stdin.write("\n")
        process.stdin.flush()

        # Get the output and error output
        output, _ = process.communicate()

        process.send_signal(signal.SIGINT)

        # Wait for the program to finish
        process.wait()

        # Check that the site has been printed out
        result = ""
        expected_text = "Password shared correctly"  # Expected text based on the last line of output
        lines = output.strip().split('\n')
        for line in lines:
            if shared_site.upper() in line:
                result = True
        self.assertTrue(result)

    def test_9_option_logged_show_passwords_shared_with_me(self):
        """Check passwords shared with me"""
        # Run the program and capture the output
        process = subprocess.Popen(['python', 'main.py'], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   universal_newlines=True, stdin=subprocess.PIPE)

        # Send option to the program
        option = '1\n'  # Desired option
        process.stdin.write(option)
        process.stdin.flush()

        # Capture username and password
        username = 'test2'  # Desired username
        password = '1'  # Desired password

        # Send username and password to the program
        process.stdin.write(username + '\n')
        process.stdin.flush()
        process.stdin.write(password + '\n')
        process.stdin.flush()

        option2 = "7\n"
        process.stdin.write(option2)
        process.stdin.flush()

        shared_site = "Netflix".upper()
        process.stdin.write(shared_site + '\n')
        process.stdin.flush()
        process.stdin.write("\n")
        process.stdin.flush()

        # Get the output and error output
        output, _ = process.communicate()

        process.send_signal(signal.SIGINT)

        # Wait for the program to finish
        process.wait()

        # Check that both the username and password are within the response.
        result_expected = ["User:test", "Password:1"]
        lines = output.strip().split('\n')
        counter = 0
        for line in lines:
            if result_expected[0] in line:
                counter += 1
            if result_expected[1] in line:
                counter += 1
        # If the counter is 2, it means that both fields have been found.
        self.assertEqual(counter, 2)

    def test_10_option_3_close_programme(self):
        """Closing of the program"""
        process = subprocess.Popen(['python', 'main.py'], stdout=subprocess.PIPE, stdin=subprocess.PIPE)

        # Send option to the programme
        option = '3\n'  # Opción deseada
        process.stdin.write(option.encode())
        process.stdin.flush()

        # Get the result
        result = process.stdout.read().decode()
        lineas = result.strip().split('\n')
        last_line = lineas[-1]

        # Expected text
        expected_text = "Thanks for using PassSworld!!"  # Expected text according to the submitted option

        # Compare the result with the expected text
        self.assertEqual(last_line, expected_text)

    def test_11_option_4_delete_all(self):
        """Delete All data"""
        process = subprocess.Popen(['python', 'main.py'], stdout=subprocess.PIPE, stdin=subprocess.PIPE)

        # Send option to the programme
        option = '4\n'  # Opción deseada
        process.stdin.write(option.encode())
        process.stdin.flush()

        # Get the result
        result = process.stdout.read().decode()
        lineas = result.strip().split('\n')
        last_line = lineas[-1]

        # Expected text
        expected_text = "Elimination successfully completed"  # Expected text according to the submitted option

        # Compare the result with the expected text
        self.assertEqual(last_line, expected_text)


# Ejecutamos los tests si se ejecuta este archivo directamente
if __name__ == '__main__':
    unittest.main()
