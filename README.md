# DubboWorkshop

18th September 2021

## Preparation

For this workshop, you are invited to actively participate by writing CodeQL queries in Visual Studio Code. To do this, you will need to have Visual Studio Code up and running.

### Running locally

1. Install Visual Studio Code. 

2. Clone the repository (https://github.com/CodeQLWorkshops/DubboWorkshop) locally. For example with the command line

```
git clone --recursive https://github.com/CodeQLWorkshops/DubboWorkshop.git
```

3. Open the repository folder in Visual Studio Code.

4. Install the CodeQL extension for Visual Studio Code, from the Visual Studio Code extensions marketplace. (Use the "Extensions" icon on the left of Visual Studio Code).

5. Click on the CodeQL icon on the left, dismiss the dialog if needed, then select "Add a CodeQL database/From an archive". Navigate to the `databases` folder and select `dubbo_2.7.8.zip`.

6. Go back to the CodeQL view (click on the CodeQL icon on the left if necessary). Hover over the database and select "Set Current Database".

7. Open the file `HelloWorld.ql` in VScode. (Use the Explorer icon on the left of Visual Studio Code, and locate the file in the root of the repository).

8. Right-click on the file, and select "CodeQL: Run query". You should see the "CodeQL Query Results" window on the right hand side.

9. Proceed to the [main content](workshop.md).


## :books: Resources
- For more advanced CodeQL development in future, you may wish to set up the [CodeQL starter workspace](https://codeql.github.com/docs/codeql-for-visual-studio-code/setting-up-codeql-in-visual-studio-code/#using-the-starter-workspace) for all languages.
- [CodeQL overview](https://codeql.github.com/docs/codeql-overview/)
- [CodeQL for Java](https://codeql.github.com/docs/codeql-language-guides/codeql-for-java/)
- [Analyzing data flow in Java](https://codeql.github.com/docs/codeql-language-guides/analyzing-data-flow-in-java/)
- [Using the CodeQL extension for VS Code](https://codeql.github.com/docs/codeql-for-visual-studio-code/)
- CodeQL on [GitHub Learning Lab](https://lab.github.com/search?q=codeql)
- CodeQL on [GitHub Security Lab](https://codeql.com)
