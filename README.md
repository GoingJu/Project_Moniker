# Project_Moniker
2023 Telemetry Engineering Code-A-Thon Submission

Project Moniker is intended to be a python application that will parse each line in our logstash configuration files and map values contained within a registry number. The registry number format will follow the indexes of the configuration files so that it provides clarity at a glance, and informatinve information on how a configuration file is structured. The intent of this data will be to use it for scanning and modifying our current repository of configuration files and may also be used as an adjuct tool for parser development.

Example of registry information:
  The sample provided below is found on lines 31 and 32 of the sample_parser:
  
      "output.principal.vendor_name"  =>  "ChAnGe!!!"
      "event.idm.read_only_udm.principal.product_name"  =>  "tHiS!!!!"
  
  I would expect it to provide an output as:
  
      "principal.vendor_name" = f1.m3.r1.udm.32
      "principal.product_name" = f1.m3.r2.udm.33
  
  Output Breakdown: 
      
      principal.product_name: Is the recorded string with 
      f1:   Located within first 'filter' index
      m3:   Is the 3rd occurrence of mutate index.
      r1:   Is the 2nd occurrence of rename index, within the 3rd mutate index.
      udm:  Is a udm field
      31:   Was found on the 31st line of the file

  Any string that is found inside of double quotes, and does not contain a value found
  in the keyword_mapping array will be considered a variable. 
  For example the string contained on line 4:
              
      "test" => ""
  
  Would provide an output as:
  
      "test" = f1.m2.r1.v1.5
  
  Explanation is that: 
  
      test:  Is the recorded string .
      f1:    Within first found filter index.
      m2:    Is the second occurrence of mutate index in the file.
      r1:    Is the first occurrence of rename within the 2nd mutate index.
      v1:    Is the 1st reported variable found in the file.
      5:     Was found on the 5th line of the file


Change History:
  project_moniker_0.1 moved to archive. Currently working on tracking nest counts     correctly

Current Output of Application:

    (venv) justin.goings@FTG10500 venv % python3 project_moniker.py /Users/justin.goings/Applications/project_moniker/conf_sample.conf -O 0 --debug
Variables:
"test" = filter0.mutate0.v1.4 (Original Line: ""test" => """, Keyword: "test", Current Context: filter0.mutate0.v1, Context Stack: ['filter0', 'filter0.mutate0'])
"test" = mutate0.v2.10 (Original Line: ""test" => """, Keyword: "test", Current Context: mutate0.v2, Context Stack: ['mutate0'])
"source" = json0.v3.15 (Original Line: "source => "message"", Keyword: "source", Current Context: json0.v3, Context Stack: ['json0'])
"source" = json0.v4.20 (Original Line: "source => "message"", Keyword: "source", Current Context: json0.v4, Context Stack: ['json0'])
"tag" = drop0.v5.26 (Original Line: "tag => "TAG_MALFORMED_ENCODING"", Keyword: "tag", Current Context: drop0.v5, Context Stack: ['drop0'])
"output" = mutate0.v9.45 (Original Line: ""output" => "event.idm.read_only_udm"", Keyword: "output", Current Context: mutate0.v9, Context Stack: ['mutate0'])
"@output" = mutate0.v10.57 (Original Line: ""@output" => "event"", Keyword: "@output", Current Context: mutate0.v10, Context Stack: ['mutate0'])

UDM Fields:
"output.principal.vendor_name" = mutate0.v6.32 (Original Line: ""output.principal.vendor_name"  =>  "ChAnGe!!!"", Keyword: "output.principal.vendor_name", Current Context: mutate0.v6, Context Stack: ['mutate0'])
"event.idm.read_only_udm.principal.product_name" = mutate0.v7.33 (Original Line: ""event.idm.read_only_udm.principal.product_name"  =>  "tHiS!!!!"", Keyword: "event.idm.read_only_udm.principal.product_name", Current Context: mutate0.v7, Context Stack: ['mutate0'])
"output.principal.event_type" = mutate0.v8.39 (Original Line: ""output.principal.event_type" => "GENERIC_EVENT"", Keyword: "output.principal.event_type", Current Context: mutate0.v8, Context Stack: ['mutate0'])

Full Output:
"filter" = filter0.f1.1 (Original Line: "filter {", Keyword: "filter", Current Context: filter0.f1, Context Stack: ['filter0'])
"mutate" = filter0.mutate0.m1.2 (Original Line: "mutate {", Keyword: "mutate", Current Context: filter0.mutate0.m1, Context Stack: ['filter0', 'filter0.mutate0'])
"replace" = filter0.mutate0.r1.3 (Original Line: "replace => {", Keyword: "replace", Current Context: filter0.mutate0.r1, Context Stack: ['filter0', 'filter0.mutate0'])
"mutate" = mutate0.m2.8 (Original Line: "mutate {", Keyword: "mutate", Current Context: mutate0.m2, Context Stack: ['mutate0'])
"replace" = mutate0.r2.9 (Original Line: "replace => {", Keyword: "replace", Current Context: mutate0.r2, Context Stack: ['mutate0'])
"json" = json0.j1.14 (Original Line: "json {", Keyword: "json", Current Context: json0.j1, Context Stack: ['json0'])
"on_error" = json0.err1.16 (Original Line: "on_error => "zerror.json"", Keyword: "on_error", Current Context: json0.err1, Context Stack: ['json0'])
"json" = json0.j2.19 (Original Line: "json {", Keyword: "json", Current Context: json0.j2, Context Stack: ['json0'])
"on_error" = json0.err2.21 (Original Line: "on_error => "zerror.json2"", Keyword: "on_error", Current Context: json0.err2, Context Stack: ['json0'])
"if" = c1.24 (Original Line: "if [zerror][json] {", Keyword: "if", Current Context: c1, Context Stack: [])
"drop" = drop0.dr1.25 (Original Line: "drop {", Keyword: "drop", Current Context: drop0.dr1, Context Stack: ['drop0'])
"mutate" = mutate0.m3.30 (Original Line: "mutate {", Keyword: "mutate", Current Context: mutate0.m3, Context Stack: ['mutate0'])
"replace" = mutate0.r3.31 (Original Line: "replace => {", Keyword: "replace", Current Context: mutate0.r3, Context Stack: ['mutate0'])
"mutate" = mutate0.m4.37 (Original Line: "mutate {", Keyword: "mutate", Current Context: mutate0.m4, Context Stack: ['mutate0'])
"replace" = mutate0.r4.38 (Original Line: "replace => {", Keyword: "replace", Current Context: mutate0.r4, Context Stack: ['mutate0'])
"mutate" = mutate0.m5.43 (Original Line: "mutate {", Keyword: "mutate", Current Context: mutate0.m5, Context Stack: ['mutate0'])
"rename" = mutate0.rn1.44 (Original Line: "rename => {", Keyword: "rename", Current Context: mutate0.rn1, Context Stack: ['mutate0'])
"statedump" = statedump0.sd1.51 (Original Line: "statedump{", Keyword: "statedump", Current Context: statedump0.sd1, Context Stack: ['statedump0'])
"label" = statedump0.l1.52 (Original Line: "label => "--------END--------END--------END--------END--------END--------END--------END--------END--------END--------"", Keyword: "label", Current Context: statedump0.l1, Context Stack: ['statedump0'])
"mutate" = mutate0.m6.55 (Original Line: "mutate {", Keyword: "mutate", Current Context: mutate0.m6, Context Stack: ['mutate0'])
"merge" = mutate0.mr1.56 (Original Line: "merge => {", Keyword: "merge", Current Context: mutate0.mr1, Context Stack: ['mutate0'])
