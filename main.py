import admin
import os
import time

ANSI_RESET = "\u001B[0m"
ANSI_BLACK = "\u001B[30m"
ANSI_RED = "\u001B[31m"
ANSI_GREEN = "\u001B[32m"
ANSI_YELLOW = "\u001B[33m"
ANSI_BLUE = "\u001B[34m"
ANSI_PURPLE = "\u001B[35m"
ANSI_CYAN = "\u001B[36m"
ANSI_WHITE = "\u001B[37m"
TAB = '\t'*7
TAB2 = '\t'*6
admin = admin.Admin()
os.system('cls')


while True:
    os.system("cls")
    "Loop that allows execution until the user indicates otherwise."
    print("\n" + ANSI_PURPLE +
          TAB2 + "     ____                  ____                              _   ____     \n" +
          TAB2 + "     |  _ \    __ _   ___  / ___|  __      __   ___    _ __  | | |  _ \   \n" +
          TAB2 + "     | |_) |  / _` | / __| \___ \  \ \ /\ / /  / _ \  | '__| | | | | | |  \n" +
          TAB2 + "     |  __/  | (_| | \__ \  ___) |  \ V  V /  | (_) | | |    | | | |_| |  \n" +
          TAB2 + "     |_|      \__,_| |___/ |____/    \_/\_/    \___/  |_|    |_| |____/     " +
          ANSI_RESET)
    print(TAB + "___________________________________________________________\n"+ANSI_YELLOW +
          TAB + "           WELCOME MENU -CHOOSE BETWEEN ACTIONS \n " +
          TAB + "########           1) Login                       ########\n " +
          TAB + "########           2) Sing Up                     ########\n " +
          TAB + "########           3) Close program               ########\n"+ANSI_RESET +
          TAB + "___________________________________________________________")
    action1 = input(TAB+ANSI_PURPLE+"Write down 1, 2 or 3: "+ANSI_RESET)
    # ---------------------- Login functionality -----------------------------
    if action1 == "1":
        os.system('cls')
        print("\n\n"+ TAB + ANSI_PURPLE+"LOGIN MENU - INTRODUCE YOUR USER INFORMATION\n"+ANSI_RESET +
              TAB + ANSI_YELLOW+"_____________________________________________\n" + ANSI_RESET)
        app_user = input(TAB + ANSI_PURPLE + "Username:    " + ANSI_RESET).upper()
        app_pass = input(TAB + ANSI_PURPLE + "Password:    " + ANSI_RESET)
        log_in_ck = admin.log_in_check_user(app_user, app_pass)
        flag = log_in_ck[0]
        user_acc = log_in_ck[1]
        err = log_in_ck[2]

        if flag:
            while True:
                os.system('cls')
                print(  "\n\n"+TAB + ANSI_YELLOW+"_________________________________________________________________\n" +
                        TAB + "             MAIN MENU - CHOOSE BETWEEN ACTIONS\n" +
                        TAB + "_________________________________________________________________\n" +
                        TAB + "########         1) See your passwords                   ########\n" +
                        TAB + "########         2) Add a new password                   ########\n" +
                        TAB + "########         3) Modify a password                    ########\n" +
                        TAB + "########         4) Share a password                     ########\n" +
                        TAB + "########         5) Delete a password                    ########\n" +
                        TAB + "########         6) Show shared passwords with other     ########\n" +
                        TAB + "########         7) Show shared passwords with me        ########\n" +
                        TAB + "########         8) Close current session                ########\n" +
                        TAB + "_________________________________________________________________"+ANSI_RESET)

                action = input(TAB+ANSI_PURPLE+"Write down 1, 2, 3, 4, 5 or 6: "+ANSI_RESET)

                if action == "1":
                    os.system('cls')
                    print("\n\n\n" + TAB + "                  SAVED PASSWORDS")
                    print(TAB + "__________________________________________________________")
                    admin.show(app_user, 'external')
                    input(TAB + ANSI_RED+"Press any key to continue: "+ANSI_RESET)

                if action == "2":
                    os.system("cls")
                    print("\n\n"+ TAB + ANSI_PURPLE+"ADD A NEW PASSWORD - INTRODUCE THE ACCOUNT INFORMATION\n"+ANSI_RESET +
                            TAB + ANSI_YELLOW+"_____________________________________________\n" + ANSI_RESET)
                    acc_site = input(TAB + ANSI_YELLOW+"Introduce the site of the account: ").upper()
                    acc_user = input(TAB + "Introduce the user of the account: ")
                    acc_pass = input(TAB + "Introduce the password of the account: "+ANSI_RESET)
                    admin.add_external_account(acc_site, app_user, acc_user, acc_pass)
                    input(TAB + ANSI_RED + "Press any key to continue: " + ANSI_RESET)
                    print('\n')
                    print('Password saved correctly')


                if action == "3":
                    os.system("cls")
                    print("\n\n\n" + TAB + "                  SAVED PASSWORDS")
                    print(TAB + "__________________________________________________________")
                    admin.show(app_user, 'external')
                    site = input(TAB + ANSI_YELLOW+"Introduce the site/application: ").upper()
                    while site == '':
                        print(TAB + "The site can not be empty")
                        site = input(TAB + ANSI_YELLOW + "Introduce the site/application: ").upper()

                    new_acc_user = input(TAB + "Introduce the new user: ")
                    while new_acc_user == '':
                        print(TAB + "The user can not be empty")
                        new_acc_user = input(TAB + "Introduce the new user: ")

                    new_acc_pass = input(TAB + "Introduce the new password: ")
                    while new_acc_pass == '':
                        print(TAB + "The password can not be empty")
                        new_acc_user = input(TAB + "Introduce the new password: ")

                    new_acc_sec_ques = input(TAB + "Introduce the new security question: ")
                    new_acc_notes = input(TAB + "Introduce the new notes: "+ANSI_RESET)
                    admin.save_external_account(site,
                                                app_user,
                                                new_acc_user,
                                                new_acc_pass,
                                                new_acc_sec_ques,
                                                new_acc_notes)

                if action == "4":
                    os.system("cls")
                    print(
                        "\n\n" + TAB + ANSI_PURPLE + "SHARE A PASSWORD - INTRODUCE THE REQUIRED DATA\n" + ANSI_RESET +
                        TAB + ANSI_YELLOW + "_____________________________________________\n" + ANSI_RESET)
                    receiving_user = input(TAB + ANSI_YELLOW+"Introduce the user which you will like to share your account: ").upper()
                    site_to_share = input(TAB + "Introduce the site of the account you want to share: "+ANSI_RESET).upper()
                    user_sites = admin.recover_json_information("./JSONS/shared_accounts.json")[app_user]['shared_with_other']
                    while site_to_share in user_sites:
                        print(TAB + ANSI_RED+"The site password is already shared "+ANSI_RESET)
                        site_to_share = input(TAB+
                            "Introduce the site of the account you want to share: " + ANSI_RESET).upper()
                    admin.share_password(app_user, receiving_user, site_to_share)
                    input(TAB + ANSI_RED+"Press any key to continue: "+ANSI_RESET)
                    print('\n')
                    print('Password shared correctly')

                if action == "5":
                    os.system("cls")
                    print("\n\n\n" + TAB + "                  SAVED PASSWORDS")
                    print(TAB + "__________________________________________________________")
                    admin.show(app_user, 'external')
                    print(TAB + ANSI_PURPLE+"Delete a password - Introduce the required data"+ANSI_RESET)
                    site = input(TAB + ANSI_YELLOW+"Introduce the site/application that you would like to delete: "+ANSI_YELLOW).upper()
                    admin.delete_password(app_user,site)

                if action == "6":
                    os.system("cls")
                    print("\n\n\n" + TAB + "                  PASSWORDS I SHARED")
                    print(TAB + "__________________________________________________________")
                    admin.show(app_user, 'shared_woth')
                    print(TAB + "__________________________________________________________")
                    input(TAB + ANSI_RED + "Press any key to continue: " + ANSI_RESET)

                if action == "7":
                    os.system("cls")
                    print("\n\n\n" + TAB + "                  PASSWORDS SHARED WITH ME")
                    print(TAB + "__________________________________________________________")
                    admin.show(app_user, 'shared_wme')
                    print(TAB + "__________________________________________________________")
                    input(TAB + ANSI_RED + "Press any key to continue: " + ANSI_RESET)

                if action == "8":
                    os.system('cls')

                    break
        else:
            print('\n')
            print(err)
            time.sleep(1)

    # ---------------------- Sing up functionality -----------------------------
    elif action1 == "2":
        os.system('cls')
        print("\n\n" + TAB + ANSI_PURPLE + "SING UP MENU - INTRODUCE YOUR USER INFORMATION\n" + ANSI_RESET +
              TAB + ANSI_YELLOW + "_____________________________________________\n" + ANSI_RESET)
        app_user = input(TAB + ANSI_PURPLE + "Username:    " + ANSI_RESET).upper()
        app_pass = input(TAB + ANSI_PURPLE + "Password:    " + ANSI_RESET)
        admin.add_user(app_user, app_pass)
        print('\n')
        print('User successfully registered')

    # ---------------------- Close functionality -----------------------------
    elif action1 == "3":
        print('\n')
        print("Thanks for using PassSworld!!")

        break

    # ---------------------- Input error functionality -----------------------------
    elif action1 == "4":
        admin.save_json_information({}, "./JSONS/app_users.json")
        admin.save_json_information({}, "./JSONS/users_external_accounts.json")
        admin.save_json_information({}, "./JSONS/shared_accounts.json")
        path = './RSA_keys'
        for f in os.listdir(path):
            os.remove(os.path.join(path, f))
        print('\n')
        print("Elimination successfully completed")
        break

    else:
        print("Error: action not possible")
