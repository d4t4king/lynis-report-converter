# lynis_report
[![Build Status](https://travis-ci.org/d4t4king/lynis_report.svg?branch=master)](https://travis-ci.org/d4t4king/lynis_report)

Manageable report from lynis text output.

## Help Statement
```
./lynis_report.pl -h|--help -v|--verbose -E|--excel -o|--output

Where:

-h|--help                       Display this useful message, then exit.
-v|--verbose                    Display more detailed output.  This is typically used for
                                debugging, but may provide insight when running into problems.
-E|--excel                      Output the report in Microsoft Excel binary format.  This
                                options is not yet implemented (NYI).
-o|--output                     Specifies the output file to print the report to.
```
* HTML out features (default)
	* Summarizes the lynis report into a single HTML file.
* Excel out features
	* Breaks out sections into worksheets.
* PDF out features
	* Copy of the HTML report ported to PDF.


## TODO:
* PDF out needs refinement
* Other output formats?
