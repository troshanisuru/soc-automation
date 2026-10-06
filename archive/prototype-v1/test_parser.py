import json
from parser import parse_wazuh_alert

def main():
    print("Reading raw Wazuh log...")
    with open('test_log.json', 'r') as file:
        raw_log = json.load(file)

    print("Parsing and Normalizing...")
    normalized_event = parse_wazuh_alert(raw_log)

    print("\n--- Normalized Output (Ready for AI) ---")
    print(normalized_event.model_dump_json(indent=2))

if __name__ == "__main__":
    main()
