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
  in the keyword_mapping or udm_keywords arrays will be considered a variable. 
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
  ~ 20231021 - project_moniker_0.1.py moved to archive. Currently working on tracking nest counts correctly
  ~ 20321020 - project_moniker created
