package org.example;


import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.Key;

public class AdvancedProxyServer {
    private static final String SECRET_KEY = "mySecretKeyForJwtSigningMySecretKeyForJwtSigning"; // 必ず十分な長さのキーを使用
    private static final Key    key        = Keys.hmacShaKeyFor(SECRET_KEY.getBytes());
    private static final String ADMIN_ROLE = "ADMIN";
    private static final String USER_ROLE  = "USER";

    public static void main(String[] args) throws IOException {
        ServerSocket serverSocket = new ServerSocket(8081);  // ポートを8081に変更
        System.out.println("Proxy server running on port 8081");

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

                System.out.println("Authorization Header: " + authHeader);

                if (authHeader != null) {
                    String[] authParts = authHeader.split(
                            "\\s+",
                            2);  // 修正：2つのパートに分割
                    System.out.println("Auth Parts Length: " + authParts.length);

                    if (authParts.length == 2) {
                        String[] bearerParts = authParts[1].trim().split(" ");
                        if (bearerParts.length == 2) {
                            String authMethod = bearerParts[0];
                            String token = bearerParts[1];
                            System.out.println("Auth Method: " + authMethod);
                            System.out.println("Token: " + token);
                            if ("Bearer".equals(authMethod)) {
                                try {
                                    String role = Jwts.parserBuilder()
                                                      .setSigningKey(key)
                                                      .build()
                                                      .parseClaimsJws(token)
                                                      .getBody()
                                                      .get(
                                                              "role",
                                                              String.class);

                                    System.out.println("Role: " + role);

                                    switch (role) {
                                        case ADMIN_ROLE ->
                                            // 管理者のリソースへのアクセス許可
                                                out.print(
                                                        "HTTP/1.1 200 OK\r\n\r\nAdmin Access Granted");
                                        case USER_ROLE ->
                                            // ユーザーのリソースへのアクセス許可
                                                out.print(
                                                        "HTTP/1.1 200 OK\r\n\r\nUser Access Granted");
                                        case null, default -> out.print(
                                                "HTTP/1.1 403 Forbidden\r\n\r\nUnauthorized Role");
                                    }
                                    if (ADMIN_ROLE.equals(role) || USER_ROLE.equals(
                                            role)) {
                                        HttpClient client =
                                                HttpClient.newHttpClient();
                                        HttpRequest request1 =
                                                HttpRequest.newBuilder()
                                                           .uri
                                                                   (new URI(
                                                                           "http://example.com"))
                                                           .build();
                                        HttpResponse<String> response =
                                                client.send(
                                                        request1,
                                                        HttpResponse.BodyHandlers.ofString());
                                        System.out.println(response.body());
                                    }
                                } catch (Exception e) {
                                    e.printStackTrace();
                                    out.print(
                                            "HTTP/1.1 403 Forbidden\r\n\r\nInvalid Token");
                                }
                            } else {
                                out.print(
                                        "HTTP/1.1 403 Forbidden\r\n\r\nUnsupported Authentication Method");
                            }
                        } else {
                            out.print(
                                    "HTTP/1.1 403 Forbidden\r\n\r\nInvalid Authorization Header");
                        }
                    } else {
                        // 認証情報がない場合
                        out.print(
                                "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Bearer realm=\"Access to proxy\"\r\n\r\n");
                    }
                    out.flush();
                }

            } catch (Exception e) {
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
