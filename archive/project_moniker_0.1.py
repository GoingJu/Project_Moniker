import re
import argparse

def parse_logstash_config(file_location, output_structure=0, debug_enabled=True):
    def get_variable_context(keyword, context_stack):
        if context_stack:
            # When a new context starts, we need to nest the current context within it.
            # For example, from f1 to f1.m1 to f1.m1.v1
            return f'{context_stack[-1]}.{keyword}{variable_count[keyword]}'
        return f'{keyword}{variable_count[keyword]}'

    def process_line(line, udm_keywords, context_stack):
        line = line.strip()
        if not line:
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
                debug_info = f'Original Line: "{line}", {context_info}'
                output_line = f'"{original_keyword}" = {current_context}.{line_number} ({debug_info})'
            else:
                output_line = f'"{original_keyword}" = {current_context}.{line_number}'

            if original_keyword not in variable_labels:
                variable_labels[original_keyword] = current_context

            # Check if the keyword contains any of the UDM substrings
            if any(udm_keyword in original_keyword for udm_keyword in udm_keywords):
                udm_fields.append(output_line)  # Append to UDM Fields list
            else:
                # Append the output line to the respective list based on the keyword
                if keyword == 'v':
                    variable_output_lines.append(output_line)
                else:
                    output_lines.append(output_line)
        else:
            # Check if the line contains variable assignments
            variable_match = re.match(r'^\s*"([^"]+)"\s*=>\s*"([^"]+)"', line)
            if variable_match:
                var_name, var_value = variable_match.groups()

                current_context = context_stack[-1] if context_stack else ""
                output_line = f'"{var_name}" = {current_context}.{line_number}'
                variable_output_lines.append(output_line)

            # Handle context changes based on start and end of blocks
            block_start_match = re.match(r'^\s*(\w+)\s*\{', line)
            block_end_match = re.match(r'^\s*\}', line)
            if block_start_match:
                keyword = block_start_match.group(1)
                context_stack.append(get_variable_context(keyword, context_stack))
            elif block_end_match:
                if context_stack:
                    context_stack.pop()  # Check if the stack is not empty before popping

    with open(file_location, 'r') as file:
        lines = file.readlines()

    variable_labels = {}
    variable_count = {}
    output_lines = []
    variable_output_lines = []
    udm_fields = []

    context_stack = []

    keyword_mapping = {
        "filter": "f",
        "mutate": "m",
        "replace": "r",
        "rename": "rn",
        "json": "j",
        "on_error": "err",
        "kv": "kv",
        "label": "l",
        "drop": "dr",
        "if": "c",
        "date": "dt",
        "csv": "csv",
        "useragent": "ua",
        "statedump": "sd",
        "merge": "mr",
    }

    udm_keywords = ["principal", "intermediary", "observer", "target", "src", "network", "security_result"]

    for line_number, line in enumerate(lines, start=1):
        process_line(line, udm_keywords, context_stack)

    if output_structure == 1:
        output_lines.sort()  # Alphabetically sort the output lines
        variable_output_lines.sort()  # Sort variable output lines

    variable_output_lines.insert(0, "Variables:")  # Add section header
    variable_output_lines = [f"{line}" for line in variable_output_lines]  # No numbering for variable outputs

    udm_fields.insert(0, "UDM Fields:")  # Add section header

    full_output_lines = output_lines.copy()
    output_lines.insert(0, "Full Output:")  # Add section header
    output_lines = [f"{line}" for line in output_lines]  # No numbering for full output

    # Add a blank line to separate "UDM Fields" and "Full Output"
    udm_fields.append("")

    # Add a blank line to the end of the variable list
    variable_output_lines.append("")

    # Print the results
    print('\n'.join(variable_output_lines + udm_fields + output_lines))  # Print variable output, UDM Fields, and full output together

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("file_location", type=str, help="Location of the configuration file")
    parser.add_argument("-O", type=int, choices=[0, 1], default=0, help="Output structure (0 = no modification, 1 = alphabetized list)")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    args = parser.parse_args()
    parse_logstash_config(args.file_location, output_structure=args.O, debug_enabled=args.debug)
