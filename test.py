import json
import sys

def get_total_runtime(speedscope_file):
    try:
        with open(speedscope_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Most common location for total captured time
        if 'profiles' in data and data['profiles']:
            profile = data['profiles'][0]  # usually we take the first/primary profile
            
            if 'startValue' in profile and 'endValue' in profile:
                start = profile['startValue']
                end = profile['endValue']
                total_seconds = end - start
                print(f"Total runtime: {total_seconds:.3f} seconds")
                print(f"                 ({total_seconds / 60:.2f} minutes)")
                return
            
            # Fallback: look in the first profile that has endValue
            for profile in data['profiles']:
                if 'endValue' in profile:
                    total = profile['endValue']
                    print(f"Total captured time: {total:.3f} seconds")
                    print(f"                      ({total / 60:.2f} minutes)")
                    return
        
        print("Could not find total runtime (no 'endValue' found in profiles)")
        
    except FileNotFoundError:
        print(f"File not found: {speedscope_file}")
    except json.JSONDecodeError:
        print("Invalid JSON format")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python total_time.py <path_to_speedscope.json>")
        print("Example:")
        print("  python total_time.py profile.speedscope.json")
        sys.exit(1)
    
    get_total_runtime(sys.argv[1])
