.PHONY: default examples
default: examples

examples: example_data/export_file_for_paedml_linux_6

example_data/export_file_for_paedml_linux_6: example_data/win_dhcp_export.csv example_data/regex_rename.csv
	./parse_windows_dhcp_leases_csv.py --input-file "$<" --rename-via-csv example_data/regex_rename.csv --ignore-fqdn-regex '(:?phone|android|privat)' --output-file "$@"
