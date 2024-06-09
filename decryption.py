import requests
import base64
import nacl.secret
import nacl.utils

# Fetch the decryption challenge
url = 'https://g5qrhxi4ni.execute-api.eu-west-1.amazonaws.com/Prod/decrypt'
response = requests.post(url)

if response.status_code == 201:
    print("POST request successful!")
    response_obj = response.json()
    challenge_id = response_obj['challengeId']
    ciphertext = response_obj['ciphertext']
    key = response_obj['key']
    nonce = response_obj['nonce']
else:
    print("POST request failed with status code:", response.status_code)
    exit(1)

print(f"ID: {challenge_id} cipher text: {ciphertext} Key: {key} Nonce: {nonce}")

# Decode the base64 data
decoded_ciphertext = base64.b64decode(ciphertext)
decoded_key = base64.b64decode(key)
decoded_nonce = base64.b64decode(nonce)

print(f"Base 64 cipher text: {decoded_ciphertext} Key: {decoded_key} Nonce: {decoded_nonce}")

# Decrypt the ciphertext using the key and nonce
box = nacl.secret.SecretBox(decoded_key)
output_decryption = box.decrypt(decoded_ciphertext, decoded_nonce)

print(f"Output decryption (raw binary): {output_decryption}")

# Encode the plaintext in base64
output_encode_b64 = base64.standard_b64encode(output_decryption)
print(f"The raw binary encoded into base64 so it can be sent in a request: {output_encode_b64}")

# JSON payload with plaintext property
payload = {"plaintext": output_encode_b64.decode('utf-8')}
print(f"plaintext: {output_encode_b64.decode('utf-8')}")

# Send DELETE request with JSON payload
delete_url = f'{url}/{challenge_id}'  # Append challengeId to URL
delete_response = requests.delete(delete_url, json=payload)

print("DELETE request response status:", delete_response.status_code)
print("DELETE request response text:", delete_response.text)

if delete_response.status_code == 204:
    print("DELETE request successful, challenge solved and deleted.")
else:
    print(f"DELETE request failed with status code: {delete_response.status_code}")
