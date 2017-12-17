r77 Rootkit fill hide files and processes that start with "$77" (without the quotes)

Example to test the effects:
 1. Run "$77-ExampleExecutable.exe"
 2. It's visible in Task Manager
 3. Install rootkit
 4. Restart Task Manager
 5. It's no longer visible in Task Manager
 6. Restart Explorer
 7. Guess what... It's hidden there, too.