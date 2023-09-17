import hashlib
import socket
import threading

#  VARS -> for bruteforce attack:
possible_chars_tuple = (
    '0',
    '1',
    '2',
    '3',
    '4',
    '5',
    '6',
    '7',
    '8',
    '9',
    'a',
    'b',
    'c',
    'd',
    'e',
    'f',
    'g',
    'h',
    'i',
    'j',
    'k',
    'l',
    'm',
    'n',
    'o',
    'p',
    'q',
    'r',
    's',
    't',
    'u',
    'v',
    'w',
    'x',
    'y',
    'z',
)

#  VARS -> for client side (communication with server):
HEADER, PORT = 2048, 5050
FORMAT, DISCONNECT_MESSAGE, PASS_CRACK_MESSAGE = 'utf-8', "!DISCONNECT!", "!CRACKED!"
SERVER = ""  # insert server IP here
ADDR = (SERVER, PORT)
server_task_messages_tuple = (
    "REQUEST-BRUTE",
    "TERMINATE-CONNECTION"
)

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(ADDR)


#  FUNCTIONS -> for bruteforce attack
def pass_combo_for_brute(curr_offset: int) -> str:
    brute_pass = "" + possible_chars_tuple[int(curr_offset % len(possible_chars_tuple))]
    curr_offset = int(curr_offset / len(possible_chars_tuple))

    while curr_offset > 0:
        brute_pass += possible_chars_tuple[int(curr_offset % len(possible_chars_tuple))]
        curr_offset = int(curr_offset / len(possible_chars_tuple))

    return brute_pass


def get_offset_from_base36(offset_base36: str) -> int:
    if len(offset_base36.replace("0", "")) < 2:
        return int(offset_base36, len(possible_chars_tuple))

    if offset_base36.replace(f"{possible_chars_tuple[0]}", "") == "":
        offset_base36 = possible_chars_tuple[1] + offset_base36[2:len(offset_base36)]
    elif offset_base36[0] == possible_chars_tuple[0]:
        new_offset_base36_str, last_seen_problem_chr_index = "", 0
        for chr_index in range(1, len(offset_base36)):
            last_seen_problem_chr_index = chr_index
            if offset_base36[chr_index] != possible_chars_tuple[0]:
                break

            offset_base36 += offset_base36[chr_index]

        new_offset_base36_str += offset_base36[last_seen_problem_chr_index: len(offset_base36)]
        offset_base36 = new_offset_base36_str

    return int(offset_base36, len(possible_chars_tuple))


def get_pass_from_hash(start_offset_base36: str, end_offset_base36: str, hash_to_crack: str) -> (str, bool):
    start_offset, end_offset = get_offset_from_base36(start_offset_base36), get_offset_from_base36(end_offset_base36)
    curr_brute_pass, is_pass_found = "", False

    print(f"base36: {start_offset_base36} -> base10: {start_offset}")
    print(f"base36: {end_offset_base36} -> base10: {end_offset}")

    for i in range(end_offset - start_offset):
        curr_brute_pass = pass_combo_for_brute(start_offset + i)

        curr_brute_hash = hashlib.md5(curr_brute_pass.encode()).hexdigest()
        is_pass_found = curr_brute_hash == hash_to_crack

        if is_pass_found:
            break

        # print(f"pass: {curr_brute_pass} -> FAILURE")

    return curr_brute_pass, is_pass_found


#  FUNCTION -> for client side (communication with server):
def send_msg_to_server(msg) -> None:
    msg_encoded = msg.encode(FORMAT)
    # server receives header message at fixed length - telling the server the length of our actual message
    msg_length = len(msg_encoded)  # length of message
    send_length = str(msg_length).encode(FORMAT)  # encoding in order to send to server
    send_length += b' ' * (HEADER - len(send_length))  # to fill header message in order for server to read it

    client.send(send_length)
    client.send(msg_encoded)


def get_message_from_server() -> str:
    return client.recv(HEADER).decode(FORMAT)


def receive_hash_and_range_from_server(msg: str) -> (str, str, str):
    # receives message from server.
    # - Returns: tuple -> (hash to crack, starting index [base36], end index [base36])
    seperator_indexes = [index for index, chr_to_find in enumerate(msg) if
                         chr_to_find == ',']  # will return only 2 indexes

    hash_to_crack = msg[0:seperator_indexes[0]]
    start_offset_base36 = msg[seperator_indexes[0] + 1:seperator_indexes[1]]
    end_offset_base36 = msg[seperator_indexes[1] + 1:len(msg)]

    return hash_to_crack, start_offset_base36, end_offset_base36


def send_bruteforce_result_to_server(resulting_pass: str, is_cracked: bool) -> None:
    # - sends result of bruteforce to the server (the resulting pass, and if it was really cracked or not)
    if is_cracked:
        send_msg_to_server(f"[{PASS_CRACK_MESSAGE}]{resulting_pass}")
    else:
        send_msg_to_server("[!CRACK FAILURE!]")


def handle_bruteforce_task_from_server(msg: str) -> bool:
    hash_to_crack, start_offset_base36, end_offset_base36 = receive_hash_and_range_from_server(msg)
    resulting_pass, is_cracked = get_pass_from_hash(start_offset_base36, end_offset_base36, hash_to_crack)

    send_bruteforce_result_to_server(resulting_pass, is_cracked)

    return is_cracked


def server_task_identifier_format(iden: str) -> str | None:
    if iden not in server_task_messages_tuple:
        print(f"[{ADDR}: TASK-READ ERROR] task received from server not parseable.")
        return None

    return f"[SERVER: {iden}]"


def handle_server(msg: str) -> None:
    curr_server_task = ""
    for task in server_task_messages_tuple:
        curr_server_task = task
        curr_server_task_format = server_task_identifier_format(task)

        if curr_server_task_format in msg:
            msg = msg.replace(curr_server_task_format, "")
            break

    if curr_server_task == "":
        print()
        return None

    if curr_server_task == server_task_messages_tuple[0]:
        handle_bruteforce_task_from_server(msg)
    elif curr_server_task == server_task_messages_tuple[1]:
        send_msg_to_server(DISCONNECT_MESSAGE)


def main():
    connected = True
    while connected:
        msg = get_message_from_server()
        handle_server(msg)

    # send_msg_to_server("[CLIENT] beginning bruteforce program.")
    # get_message_from_server()
    #
    # my_pass = "1234"
    # my_hash = hashlib.md5(my_pass.encode()).hexdigest()  # hash to crack
    #
    # send_msg_to_server(f"[CLIENT] hash to bruteforce: {my_hash}")
    # get_message_from_server()
    #
    # cracked_pass, is_successful = get_pass_from_hash("0", "fffffffffff", possible_chars_tuple, my_hash)
    #
    # send_msg_to_server(f"[CLIENT] reached={cracked_pass},isPass={is_successful}")
    # get_message_from_server()
    #
    # send_msg_to_server(DISCONNECT_MESSAGE)
    # get_message_from_server()


if __name__ == "__main__":
    main()
