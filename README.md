# Password Auditor

This is a simple command-line tool that checks the strength of passwords stored in a text file.

The program reads a file where **each line is a single password**, analyses them, and prints a summary
report: how many passwords are weak/medium/strong, average length, and a list of the weakest passwords
with warnings.


# What the program does
For each password the program calculates:

*length

*whether it contains lowercase, uppercase, digits and symbols

*a numeric score

*strength level: WEAK, MEDIUM, or STRONG

*list of warnings (too short, simple pattern, very common password, etc.)

# Then it prints:

*total number of passwords

*minimum, maximum and average length

*average score

*how many passwords are weak/medium/strong

*list of the weakest passwords with explanations

*a short detailed list for the first few passwords

## Example of Using:

password_samples.txt was used

![Screenshot1](image/Step_1.png)
![Screenshot2](image/Outcome.png)




## Requirements

- Python 3.8+  
- No third-party libraries are required. The standard library is enough.

To be safe, you can still run:

```bash
pip install -r requirements.txt
