import re
import argparse

# Define a function to parse a Logstash configuration file.
def parse_logstash_config(file_location, output_structure=0, debug_enabled=True):
    def get_variable_context(keyword, context_stack):
        if context_stack:
            return f'{context_stack[-1]}.{keyword}{variable_count[keyword]}'
        return f'f1.{keyword}{variable_count[keyword]}'

    def process_line(line, udm_keywords, context_stack):
        line = line.strip()

        if line.startswith('#') or not line:
            return

        # Check if the line contains a block start or end
        block_start_match = re.match(r'^\s*(\w+)\s*\{', line)
        block_end_match = re.match(r'^\s*\}', line)
        if block_start_match:
            keyword = block_start_match.group(1)
            context_stack.append(get_variable_context(keyword, context_stack))
            if keyword != keyword_mapping:
                nesting_level[0] += 1
                variable_count[keyword] += 1 
        elif block_end_match:
            if context_stack:
                context_stack.pop()
                nesting_level[0] -= 1
            return

        keyword_match = re.match(r'^\s*("[^"]+"|\w+)', line)
        if keyword_match:
            keyword = keyword_match.group(1).strip('"')
            original_keyword = keyword
            keyword = keyword_mapping.get(keyword, 'v')

            if keyword not in variable_count:
                variable_count[keyword] = 1
            else:
                variable_count[keyword] += 1

            current_context = get_variable_context(keyword, context_stack)

            if debug_enabled:
                context_info = f'Current Context: {current_context}, Context Stack: {context_stack}'
                debug_info = f'Original Line: "{line}", Keyword: "{original_keyword}", {context_info}'
                output_line = f'"{original_keyword}" = {current_context}.{line_number} ({debug_info})'
            else:
                output_line = f'"{original_keyword}" = {current_context}.{line_number}'

            if original_keyword not in variable_labels:
                variable_labels[original_keyword] = current_context

            if any(udm_keyword in original_keyword for udm_keyword in udm_keywords):
                udm_fields.append(output_line)
            else:
                if keyword == 'v':
                    variable_output_lines.append(output_line)
                else:
                    output_lines.append(output_line)

    # Open and read the Logstash configuration file.
    with open(file_location, 'r') as file:
        lines = file.readlines()

    # Initialize variables to store parsing results.
    variable_labels = {}
    variable_count = {
        'filter': 0,  # Initialize variable_count with all possible keywords
        'mutate': 0,
        'array_function': 0,
        'replace': 0,
        'rename': 0,
        'json': 0,
        'on_error': 0,
        'kv': 0,
        'else': 0,
        'grok': 0,
        'label': 0,
        'drop': 0,
        'if': 0,
        'date': 0,
        'csv': 0,
        'useragent': 0,
        'statedump': 0,
        'merge': 0,
        'v': 0 
    }
    
    output_lines = []
    variable_output_lines = []
    udm_fields = []

    context_stack = []
    nesting_level = [1]

    # Define a mapping for keywords and a list of UDM keywords.
    
    keyword_mapping = {
        "array_function": "af",
        "filter": "f",
        "mutate": "m",
        "replace": "r",
        "rename": "rn",
        "json": "j",
        "grok": "gr",
        "on_error": "err",
        "kv": "kv",
        "else": "el",
        "label": "l",
        "drop": "dr",
        "if": "c",
        "date": "dt",
        "csv": "csv",
        "useragent": "ua",
        "statedump": "sd",
        "merge": "mr",
        "v": "v"
    }
    udm_keywords = ["principal", "intermediary", "observer", "target", "src", "network", "security_result", "metadata"]

    # Process each line in the configuration file.
    for line_number, line in enumerate(lines, start=1):
        process_line(line, udm_keywords, context_stack)

    # Sort the output if requested.
    if output_structure == 1:
        variable_output_lines.sort()
        udm_fields.sort()
        output_lines.sort()

    # Organize and format the output.
    variable_output_lines.insert(0, "Variables:")
    variable_output_lines = [f"{line}" for line in variable_output_lines]

    udm_fields.insert(0, "UDM Fields:")
    udm_fields = [f"{line}" for line in udm_fields]

    full_output_lines = output_lines.copy()
    output_lines.insert(0, "Full Output:")
    output_lines = [f"{line}" for line in output_lines]

    udm_fields.append("")  # Add a blank line between UDM Fields and Full Output
    variable_output_lines.append("")  # Add a blank line at the end of the variable list

    # Include a page break (blank line) before the nesting level.
    output_lines.append("")  # This adds a blank line

    # Include nesting level count.
    nesting_count_line = f"Nesting Levels: {nesting_level[0]}"
    output_lines.append(nesting_count_line)

    # Print the results.
    print('\n'.join(variable_output_lines + udm_fields + output_lines))

if __name__ == "__main__":
    # Set up command-line argument parsing.
    parser = argparse.ArgumentParser()
    parser.add_argument("file_location", type=str, help="Location of the configuration file")
    parser.add_argument("-O", type=int, choices=[0, 1], default=0, help="Output structure (0 = no modification, 1 = alphabetized list)")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    args = parser.parse_args()

    # Call the parse_logstash_config function with the provided arguments.
    parse_logstash_config(args.file_location, output_structure=args.O, debug_enabled=args.debug)
