package org.example;

import org.example.Exceptions.InvalidKeyException;

import java.io.*;
import java.nio.file.Files;
import java.util.List;
import java.util.Scanner;

public class CLI {

    private boolean exitState = false;

    public CLI() {
    }

    public void start() {
        Scanner scanner = new Scanner(System.in);
        System.out.println("Welcome!");
        System.out.println("Enter Master Key: ");
        System.out.print("> ");
        String masterKey = scanner.nextLine();
        MiddleOutFiestelCipher middleOutFiestelCipher = new MiddleOutFiestelCipher(masterKey);

        File file = new File("vault.txt");
        if ( !checkFileExists(file) ) {
            createVaultFile(file);
        }

        String input;
        do {
            System.out.print("> ");
            input = scanner.nextLine();
            commandRunner(input, file, middleOutFiestelCipher);
        } while (!this.exitState);

    }

    private void commandRunner(String command, File file, MiddleOutFiestelCipher middleOutFiestelCipher) {
        String[] commandParts = command.split("\\.");
        switch (commandParts[0]){
            case "hlp":
                System.out.println("hlp -> Returns list of commands.");
                System.out.println("shw -> Returns list of password initializers.");
                System.out.println("enc.{PASSWORD}.{INITIALIZER} -> " +
                        "Encrypts a password with initializer for future access. Use without '{', '}'.");
                System.out.println("dec.{INITIALIZER} -> Returns String of decrypted password. Use without '{', '}'.");
                System.out.println("del.{INITIALIZER} -> Removes encrypted password and initializer from storage.");
                System.out.println("ext -> Exit the application.");
                break;

            case "shw":
                try {
                    Scanner fileScanner = new Scanner(file);
                    while ( fileScanner.hasNextLine() ) {
                        String[] lineParts = fileScanner.nextLine().split(":");
                        System.out.println(lineParts[0]);
                    }
                } catch (FileNotFoundException e) {
                    throw new RuntimeException(e);
                }
                break;

            case "enc":
                String encryptedPassword = middleOutFiestelCipher.encrypt(commandParts[1], commandParts[2]);
                try {
                    FileWriter fileWriter = new FileWriter(file, true);
                    fileWriter.write(commandParts[2] + ":" + encryptedPassword + "\n");
                    System.out.println("Password encrypted successfully!");
                    fileWriter.close();
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
                break;

            case "dec":
                boolean foundPassword = false;
                try {
                    Scanner fileScanner = new Scanner(file);
                    while ( fileScanner.hasNextLine() ) {
                        String[] encryption = fileScanner.nextLine().split(":");
                        if ( encryption[0].equals(commandParts[1]) ) {
                            System.out.println("Password for " + commandParts[1] + ": " + middleOutFiestelCipher.decrypt(commandParts[1], encryption[1]));
                            foundPassword = true;
                        }
                    }
                    if ( !foundPassword ) {
                        System.out.println("Password not found.");
                    }
                } catch (FileNotFoundException e) {
                    throw new RuntimeException(e);
                } catch (InvalidKeyException e) {
                    System.out.println("Incorrect master key used.");
                }
                break;

            case "del":
                try {
                    List<String> fileLines = Files.readAllLines(file.toPath());
                    fileLines.removeIf( l -> l.startsWith(commandParts[1]) );
                    Files.write(file.toPath(), fileLines);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
                break;

            case "ext":
                setExitState();
                break;

            default:
                System.out.println("Invalid command! Type 'hlp' to list all valid commands.");
                break;
        }
    }

    private void createVaultFile(File filePath) {
        try {
            filePath.createNewFile();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private boolean checkFileExists(File filePath) {
        return filePath.isFile();
    }

    private void setExitState() {
        this.exitState = true;
    }

}
