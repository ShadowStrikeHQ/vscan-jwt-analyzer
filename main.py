#!/usr/bin/env python3

import argparse
import json
import logging
import sys
import base64
import hashlib
import hmac

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define a custom exception for JWT analysis errors
class JWTAnalysisError(Exception):
    """Custom exception for JWT analysis errors."""
    pass

def setup_argparse():
    """Sets up the argument parser for the CLI."""
    parser = argparse.ArgumentParser(description="Analyzes JWT (JSON Web Tokens) for common vulnerabilities.")
    parser.add_argument("jwt", help="The JWT to analyze.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output (debug logging).")
    return parser

def decode_jwt_header(jwt):
    """Decodes the header of a JWT.

    Args:
        jwt (str): The JWT.

    Returns:
        dict: The decoded header as a dictionary.

    Raises:
        JWTAnalysisError: If the header cannot be decoded.
    """
    try:
        header_encoded = jwt.split(".")[0]
        header_decoded = base64.urlsafe_b64decode(header_encoded + '=' * (4 - len(header_encoded) % 4)).decode('utf-8')
        return json.loads(header_decoded)
    except (IndexError, json.JSONDecodeError, UnicodeDecodeError) as e:
        raise JWTAnalysisError(f"Error decoding JWT header: {e}")

def decode_jwt_payload(jwt):
    """Decodes the payload of a JWT.

    Args:
        jwt (str): The JWT.

    Returns:
        dict: The decoded payload as a dictionary.

    Raises:
        JWTAnalysisError: If the payload cannot be decoded.
    """
    try:
        payload_encoded = jwt.split(".")[1]
        payload_decoded = base64.urlsafe_b64decode(payload_encoded + '=' * (4 - len(payload_encoded) % 4)).decode('utf-8')
        return json.loads(payload_decoded)
    except (IndexError, json.JSONDecodeError, UnicodeDecodeError) as e:
        raise JWTAnalysisError(f"Error decoding JWT payload: {e}")


def analyze_algorithm(header):
    """Analyzes the 'alg' field in the JWT header for weak or insecure algorithms.

    Args:
        header (dict): The decoded JWT header.

    Returns:
        list: A list of findings related to the algorithm.
    """
    findings = []
    alg = header.get("alg")

    if not alg:
        findings.append("Warning: 'alg' field is missing.  This could indicate a serious vulnerability.")
        return findings

    alg = alg.lower()

    if alg == "none":
        findings.append("CRITICAL: 'alg' is 'none'. Signature verification is disabled. HIGHLY VULNERABLE!")
    elif alg in ["hmacsha256", "hmacsha384", "hmacsha512"]:
        findings.append(f"Info: Algorithm is {alg}, which is an HMAC algorithm.")
    elif alg in ["rs256", "rs384", "rs512", "es256", "es384", "es512"]:
        findings.append(f"Info: Algorithm is {alg}, which is an asymmetric algorithm.")
    else:
        findings.append(f"Warning: Algorithm '{alg}' is not a standard or recommended algorithm.  Investigate further.")

    return findings

def analyze_jwt(jwt):
    """Analyzes a JWT for common vulnerabilities.

    Args:
        jwt (str): The JWT to analyze.

    Returns:
        dict: A dictionary containing the analysis results.
    """
    results = {
        "header_analysis": [],
        "payload_analysis": [],
        "general_analysis": []
    }

    try:
        header = decode_jwt_header(jwt)
        payload = decode_jwt_payload(jwt)

        results["header"] = header
        results["payload"] = payload

        # Algorithm Analysis
        results["header_analysis"].extend(analyze_algorithm(header))

        # Check for common claims in payload
        if "exp" not in payload:
            results["payload_analysis"].append("Warning: 'exp' (expiration time) claim is missing. JWT might not expire.")

        if "iat" not in payload:
            results["payload_analysis"].append("Warning: 'iat' (issued at) claim is missing.")
            
        if "nbf" not in payload:
            results["payload_analysis"].append("Warning: 'nbf' (not before) claim is missing.")


    except JWTAnalysisError as e:
        results["general_analysis"].append(f"Error: {e}")
    except Exception as e:
        results["general_analysis"].append(f"Unexpected error during JWT analysis: {e}")


    return results


def verify_signature(jwt, secret=""):
    """
    Attempts to verify the JWT signature using a provided secret.
    This is a rudimentary verification and should not be relied upon in production.

    Args:
        jwt (str): The JWT to verify.
        secret (str): The secret key to use for verification.  Defaults to an empty string.

    Returns:
        bool: True if the signature is likely valid, False otherwise.
    """

    try:
        header_b64, payload_b64, signature_b64 = jwt.split(".")
        header = base64.urlsafe_b64decode(header_b64 + "==").decode("utf-8")
        header_json = json.loads(header)
        alg = header_json.get("alg")

        message = header_b64 + "." + payload_b64

        if alg.lower() in ["hmacsha256", "hmacsha384", "hmacsha512"]:
            if not secret:
                logging.warning("Secret not provided. Signature verification cannot be performed reliably.")
                return False

            # Determine the appropriate hash algorithm based on the 'alg' header.
            if alg.lower() == "hmacsha256":
                hash_algorithm = hashlib.sha256
            elif alg.lower() == "hmacsha384":
                hash_algorithm = hashlib.sha384
            elif alg.lower() == "hmacsha512":
                hash_algorithm = hashlib.sha512
            else:
                logging.error(f"Unsupported HMAC algorithm: {alg}")
                return False

            try:
                signature = hmac.new(
                    secret.encode("utf-8"),
                    message.encode("utf-8"),
                    hash_algorithm
                ).digest()
                expected_signature_b64 = base64.urlsafe_b64encode(signature).rstrip(b"=").decode("utf-8")

                return expected_signature_b64 == signature_b64

            except Exception as e:
                 logging.error(f"Error during signature verification: {e}")
                 return False
        elif alg.lower() == "none":
            logging.warning("Signature verification skipped due to 'alg' being 'none'.")
            return True # Technically, it's valid as no signature is present.

        else:
             logging.warning(f"Signature verification not implemented for algorithm: {alg}")
             return False # Indicate that we can't verify.

    except Exception as e:
        logging.error(f"Error during signature verification setup: {e}")
        return False


def print_analysis_results(results):
    """Prints the analysis results in a human-readable format.

    Args:
        results (dict): The analysis results dictionary.
    """

    print("---------------- JWT Analysis Report ----------------")
    if "header" in results:
        print("\nHeader:")
        print(json.dumps(results["header"], indent=4))
    if "payload" in results:
        print("\nPayload:")
        print(json.dumps(results["payload"], indent=4))

    print("\nFindings:")

    if results["header_analysis"]:
        print("\nHeader Analysis:")
        for finding in results["header_analysis"]:
            print(f"- {finding}")

    if results["payload_analysis"]:
        print("\nPayload Analysis:")
        for finding in results["payload_analysis"]:
            print(f"- {finding}")

    if results["general_analysis"]:
        print("\nGeneral Analysis:")
        for finding in results["general_analysis"]:
            print(f"- {finding}")
    print("-----------------------------------------------------")


def main():
    """Main function to parse arguments, analyze the JWT, and print results."""
    parser = setup_argparse()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Verbose mode enabled.")

    try:
        jwt = args.jwt
        if not jwt:
             print("Error: JWT must be provided.")
             sys.exit(1)

        analysis_results = analyze_jwt(jwt)
        print_analysis_results(analysis_results)

        # Example of offensive tool usage - Attempt to verify signature
        # This is illustrative.  Don't automatically assume the secret is "secret"
        if verify_signature(jwt, secret="secret"):
            print("\n[+] Signature verification with secret 'secret' appears to be successful (This does not guarantee validity!)")
        else:
             print("\n[-] Signature verification with secret 'secret' failed or was not attempted.")


    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        sys.exit(1)



if __name__ == "__main__":
    main()