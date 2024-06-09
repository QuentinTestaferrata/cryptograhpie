import base64
import hashlib
import requests
import multiprocessing

def calculate_hash(prefix, message):
    '''Calculate BLAKE2b hash of the prefix concatenated with the message.'''
    hash_input = prefix + message
    return hashlib.blake2b(hash_input, digest_size=32).digest()

def find_prefix_with_range(start, end, byte_length, message, results_queue):
    '''Find a valid prefix within a specified range and byte length.'''
    for candidate in range(start, end):
        prefix = candidate.to_bytes(byte_length, byteorder='big')
        hash_result = calculate_hash(prefix, message)
        if hash_result[:2] == b'\x00\x00':
            results_queue.put((prefix, hash_result))
            return

def process_ranges(byte_length, num_workers, message, results_queue):
    '''Divide the search range among multiple worker processes.'''
    range_size = (1 << (8 * byte_length)) // num_workers
    workers = []
    for i in range(num_workers):
        start = i * range_size
        end = start + range_size if i < num_workers - 1 else (1 << (8 * byte_length))
        worker = multiprocessing.Process(target=find_prefix_with_range, args=(start, end, byte_length, message, results_queue))
        workers.append(worker)
        worker.start()

    for worker in workers:
        worker.join()

def find_valid_prefix(message):
    '''Attempt to find a valid prefix by checking across multiple byte lengths.'''
    num_workers = 4  # Adjust based on your CPU
    results_queue = multiprocessing.Queue()
    for byte_length in range(2, 5):  # Trying 2, 3, and 4 byte prefixes
        process_ranges(byte_length, num_workers, message, results_queue)
        if not results_queue.empty():
            return results_queue.get()
    return None

def make_post_request():
    url = "https://g5qrhxi4ni.execute-api.eu-west-1.amazonaws.com/Prod/hash"
    response = requests.post(url)
    if response.status_code == 201:
        data = response.json()
        print(f"here is the data: {data}")
        message_b64 = data["message"]
        challenge_id = data["challengeId"]
        return message_b64, challenge_id
    else:
        print("Failed to get challenge:", response.status_code)
        return None, None

def make_delete_request(challenge_id, valid_prefix_b64):
    url = f"https://g5qrhxi4ni.execute-api.eu-west-1.amazonaws.com/Prod/hash/{challenge_id}"
    # headers = {'Content-Type': 'application/json'}
    data = {"prefix": valid_prefix_b64}
    response = requests.delete(url, json=data)
    print("Delete request response status:", response.status_code)
    print("Response body:", response.text)

if __name__ == '__main__':
    message_b64, challenge_id = make_post_request()
    if message_b64 and challenge_id:
        message = base64.standard_b64decode(message_b64)
        result = find_valid_prefix(message)
        if result:
            prefix, hash_result = result
            valid_prefix_b64 = base64.b64encode(prefix).decode('utf-8')
            print(f"Found valid prefix: {valid_prefix_b64}")
            print(f"Corresponding hash (base64): {base64.b64encode(hash_result).decode('utf-8')}")
            make_delete_request(challenge_id, valid_prefix_b64)
        else:
            print("No valid prefix found after trying all functions.")
    else:
        print("Could not retrieve challenge details.")