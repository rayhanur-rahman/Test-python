import os

# Function to read a file, but uses an insecure input method
def read_user_file_insecure(filename):
    """
    INSECURE: Allows arbitrary file path input without sanitization,
    making it vulnerable to Directory Traversal.
    """
    base_path = "/app/data_files/"
    full_path = base_path + filename
    print(f"Attempting to read file: {full_path}")

    # Vulnerability 1: Directory Traversal
    # A user could input '../etc/passwd' to read sensitive system files.
    try:
        with open(full_path, 'r') as f:
            print("--- File Content ---")
            print(f.read())
            print("--------------------")
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

# Function to execute a mathematical expression from user input
def calculate_expression_insecure(expression):
    """
    INSECURE: Uses the built-in eval() function directly on unsanitized user input,
    making it vulnerable to Remote Code Execution (RCE).
    """
    print(f"Attempting to evaluate expression: '{expression}'")
    try:
        # Vulnerability 2: Insecure use of eval()
        # A user could input '__import__("os").system("ls /")' to execute system commands.
        result = eval(expression)
        print(f"Result: {result}")
    except NameError:
        print("Error: Invalid name or function in expression.")
    except Exception as e:
        print(f"An error occurred during evaluation: {e}")

# Main execution loop for demonstration
if __name__ == "__main__":
    print("--- Insecure Application Demonstration ---")

    # Demo of Directory Traversal vulnerability
    print("\n[Demo 1: Directory Traversal via Path Input]")
    # A safe input would be: "document.txt"
    # An *exploit attempt* could be: "../../secrets/app_config.ini" (assuming relative path)
    read_user_file_insecure(input("Enter filename to read (e.g., test.txt): "))

    # Demo of Remote Code Execution (RCE) via eval()
    print("\n[Demo 2: Remote Code Execution via eval()]")
    # A safe input would be: "10 + 5 * 2"
    # An *exploit attempt* could be: "__import__('os').getcwd()"
    calculate_expression_insecure(input("Enter a math expression to evaluate (e.g., 5*5): "))

    print("\n--- Demonstration Complete ---")
