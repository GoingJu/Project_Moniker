import re
import argparse

# Defines a function to parse a Logstash configuration file.
def parse_logstash_config(file_location, output_structure=0, debug_enabled=True):
    # Initialize variables to storeresults.
    _count = [0] #<DEBUG>
    output_lines = []
    variable_output_lines = []
    udm_fields = []
    context_stack = []
    variable_labels = {}
    variables = set()
    nesting_level = [1]
    
    # Initialize command_count with all possible keywords
    command_count = {
        '@output': 0,
        'add': 0,
        'add_field': 0,
        'array_function': 0,
        'convert': 0,
        'csv': 0,
        'date': 0,
        'drop': 0,
        'else': 0,
        'event.idm.read_only_udm.': 0,
        'filter': 0,
        'grok': 0,
        'if': 0,
        'json': 0,
        'kv': 0,
        'label': 0,
        'lowercase': 0,
        'match': 0,
        'merge': 0,
        'mutate': 0,
        'on_error': 0,
        'overwrite': 0,
        'rebase': 0,
        'rename': 0,
        'replace': 0,
        'ruby': 0,
        'statedump': 0,
        'udm': 0,
        'useragent': 0
    }
    # Define mapping for keywords and a list of UDM keywords.
    keyword_mapping = {
        "@output": "end",
        "add": "ad",
        "add_field": "af",
        "array_function": "ar",
        "convert": "cv",
        "csv": "csv",
        "date": "dt",
        "drop": "dr",
        "else": "el",
        "el": "el",
        "event.idm.read_only_udm.": "udm",
        "filter": "f",
        "grok": "gr",
        "if": "c",
        "json": "j",
        "kv": "kv",
        "label": "l",
        "lowercase": "lwc",
        "match": "ma",
        "merge": "mr",
        "mutate": "mu",
        "on_error": "err",
        "rebase": "rb",
        "rename": "rn",
        "replace": "r",
        "ruby": "rb",
        "statedump": "sd",
        "useragent": "ua"
    }   
    #All the major Chronicle UDM categories that can be present
    udm_keywords = ["action", "category", "id", "intermediary", "metadata", "network", "observer", "principal", "security_result", "src", "target"]

    # Open and read the Logstash configuration file.
    with open(file_location, 'r') as file:
        lines = file.readlines()

    # #Explanation for def get_variable_context
    # 1) Checking the context stack:
    # 2) Generating the context string when the stack is not empty:
    def get_variable_context(keyword, context_stack):
        #print(f"context stack: {keyword}")##DEBUG COMMENT OUT
        if context_stack:
            context_parts = []
            for ctx in context_stack:
                context_parts.append(f'{keyword_mapping[ctx]}{command_count[ctx]}')
            return '.'.join(context_parts)
        return f'{keyword_mapping[keyword]}{command_count[keyword]}'
    
    # Define a function to process each line.
    def process_line(line, line_number, udm_keywords, context_stack):
        _count[0] += 1 #DEBUG TOOL REMOVE THIS
        # Remove blank space from the beginning of string       
        line = line.strip()
        # ignore commented lines
        if line.startswith('#') or not line:
            return
        
        # Define specific UDM leading string to remove
        leading_string1 = "event.idm.read_only_udm."
        leading_string2 = "output."
        # Regular expression to match the leading string inside double quotes
        leading_string_regex1 = rf'^"{re.escape(leading_string1)}|^"{re.escape(leading_string2)}'
        
        # Remove the leading string if it's at the start of the line inside double quotes
        if re.match(leading_string_regex1, line):
            line = re.sub(leading_string_regex1, '"', line, 1)

        # Check if the line contains a block start or end   
        block_start_match = re.match(r'^\s*([\w\[\]]+).*\{$|.*\{$', line)
        if block_start_match:
            keyword = block_start_match.group(1) # sample of group data ('mutate', None)
            context_stack.append(keyword)
        
            if keyword in keyword_mapping:
                command_count[keyword] += 1
                nesting_level[0] += 1
        
        block_end_match = re.match(r'^\s*\}$|^(\w+)\}$|.*\}$', line)  
        if block_end_match:
            #print(f"{_count} Block end matched: {block_end_match.groups()}")
            if context_stack:
                context_stack.pop()
                nesting_level[0] -= 1
            return 
        
        # # Debugging prints#########################################################
        # print(f"Processing line: '{line}'")
        # if block_start_match:
        #     print(f"{_count} Block start matched: {block_start_match.groups()}")
        # else:
        #     print("Block start not matched")

        # if block_end_match:
        #     print(f"{_count} Block end matched: {block_end_match.groups()}")
        # else:
        #     print("Block end not matched")
        # ############################################################################

        # This portion is going to check the matches and verify
        # the values that don't map to keyword_mapping
        # so that they can be checked as declared variables
        keyword_match = re.match(r'^\s*("[^"]+"|\w+).*', line)
        variable_match = re.search(r'%\{([A-Za-z0-9_]+)\}', line)
        if keyword_match:
            keyword = keyword_match.group(1).strip('"')
            if variable_match:  # Check if variable_match is not None
                variable = variable_match.group(1)
            else:
                variable = None
            original_keyword = keyword
            keyword_mapped = keyword_mapping.get(keyword)

            if keyword_mapped is None:
                if any(udm_keyword in original_keyword for udm_keyword in udm_keywords):
                    current_context = get_variable_context('udm', context_stack)
                    if debug_enabled:
                        context_info = f'Current Context: {current_context}, Context Stack: {context_stack}'
                        debug_info = f'Original Line: "{line}", Keyword: "{original_keyword}", {context_info}'
                        output_line = f'"{original_keyword}" = {current_context}.{line_number} ({debug_info})'
                    else:
                        output_line = f'"{original_keyword}" = {current_context}.{line_number}'

                    udm_fields.append(output_line)
                else:
                    variables.add(original_keyword)
                return  # Skip processing if keyword is not found in mapping and not a UDM field

            if keyword_mapped not in command_count:
                command_count[keyword_mapped] = 1
            else:
                command_count[keyword_mapped] += 1

            current_context = get_variable_context(keyword_mapped, context_stack)
            if current_context is None:
                return  # Skip if the context is invalid

            if debug_enabled:
                context_info = f'Current Context: {current_context}, Context Stack: {context_stack}'
                debug_info = f'Original Line: "{line}", Keyword: "{original_keyword}", {context_info}'
                output_line = f'"{original_keyword}" = {current_context}.{line_number} ({debug_info})'
            else:
                output_line = f'"{original_keyword}" = {current_context}.{line_number}'

            if original_keyword not in variable_labels:
                variable_labels[original_keyword] = current_context

            if any(udm_keywords in original_keyword for udm_keywords in udm_keywords):
                udm_fields.append(output_line)
            else:
                output_lines.append(output_line)
            
            # Add the variable and its context to variable_output_lines
            if variable and variable not in variable_labels:
                variable_output_lines[variable] = current_context   
   
    # Process each line in the configuration file.
    for line_number, line in enumerate(lines, start=1):
        process_line(line, line_number, udm_keywords, context_stack)

    # Sort the output if requested.
    if output_structure == 1:
        sorted_variables = sorted(variables)
        variable_output_lines = ["Variables:"] + [f"{variable}" for variable in sorted_variables]
    else:
        variable_output_lines = [f"Variables: {variable}" for variable in variables]
        variable_output_lines.insert(0, "Variables:")

    # # Organize and format the output.
    variable_output_lines = [f"{variable}" for variable in variables]
    variable_output_lines.insert(0, "")
    variable_output_lines.insert(1, "Variables:")

    #print(f"variable output lines{variable_output_lines}") #<DEBUG-REMOVE>

    udm_fields = [f"{line}" for line in udm_fields]

    output_lines.insert(0, "Full Output:")
    output_lines = [f"{line}" for line in output_lines + udm_fields]

    udm_fields.insert(0, "UDM Fields:")
    udm_fields.append("")  # Add a blank line between UDM Fields and Full Output
    variable_output_lines.append("")  # Add a blank line at the end of the variable list

    # Include a page break (blank line) before the nesting level.
    output_lines.append("")

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
