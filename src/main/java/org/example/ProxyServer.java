package org.example;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Base64;

public class ProxyServer {
    private static final String USERNAME = "user";
    private static final String PASSWORD = "password";

    public static void main(String[] args) throws IOException {
        ServerSocket serverSocket = new ServerSocket(8080);
        System.out.println("Proxy server running on port 8080");

        while (true) {
            Socket clientSocket = serverSocket.accept();
            new Thread(new ClientHandler(clientSocket)).start();
        }
    }

    static class ClientHandler implements Runnable {
        private Socket clientSocket;

        public ClientHandler(Socket clientSocket) {
            this.clientSocket = clientSocket;
        }

        @Override
        public void run() {
            try (BufferedReader in = new BufferedReader(new InputStreamReader(
                    clientSocket.getInputStream()));
                    PrintWriter out = new PrintWriter(
                            clientSocket.getOutputStream(),
                            true)
            ) {

                String inputLine;
                StringBuilder request = new StringBuilder();

                while ((inputLine = in.readLine()) != null && ! inputLine.isEmpty()) {
                    request.append(inputLine).append("\n");
                }

                String requestHeader = request.toString();
                System.out.println("Request: \n" + requestHeader);

                String authHeader = null;
                for (String line : requestHeader.split("\n")) {
                    if (line.startsWith("Authorization:")) {
                        authHeader = line;
                        break;
                    }
                }

                if (authHeader != null) {
                    String[] authParts = authHeader.split(" ");
                    if (authParts.length == 2 && "Basic".equals(authParts[0])) {
                        String decodedAuth = new String(Base64.getDecoder()
                                                              .decode(authParts[1].trim()));
                        if (USERNAME.equals(decodedAuth.split(":")[0]) && PASSWORD.equals(
                                decodedAuth.split(":")[1])) {
                            // 認証成功
                            out.print(
                                    "HTTP/1.1 200 OK\r\n\r\nProxy Authentication Successful");
                        } else {
                            // 認証失敗
                            out.print(
                                    "HTTP/1.1 403 Forbidden\r\n\r\nAuthentication Failed");
                        }
                    } else {
                        out.print(
                                "HTTP/1.1 403 Forbidden\r\n\r\nUnsupported Authentication Method");
                    }
                } else {
                    // 認証情報がない場合
                    out.print(
                            "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"Access to proxy\"\r\n\r\n");
                }
                out.flush();
            } catch (IOException e) {
                e.printStackTrace();
            } finally {
                try {
                    clientSocket.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }
}
