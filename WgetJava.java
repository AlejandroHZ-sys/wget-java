/*      VERSION FINAL    */
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.regex.*;
import javax.net.ssl.*;
import java.security.cert.X509Certificate;
import java.util.zip.*;

public class WgetJava {
    private static final String USER_AGENT = "WgetJava/1.0";
    private static final int DEFAULT_PORT = 80;
    private static final int HTTPS_PORT = 443;
    
    private boolean recursiveMode = false;
    private int threadPoolSize = 10;
    private int maxTries = 3;
    private int maxDepth = 10;
    private String baseUrl;
    private String baseHost;
    private String basePath;
    
    private Set<String> visitedUrls = ConcurrentHashMap.newKeySet();
    private Set<String> pendingUrls = ConcurrentHashMap.newKeySet();
    private ExecutorService threadPool;
    private Semaphore downloadSemaphore;
    private CountDownLatch downloadLatch;
    private Map<String, Integer> urlTypes = new ConcurrentHashMap<>();
    
    public static void main(String[] args) {
        WgetJava wget = new WgetJava();
        wget.showSyntax();
        
        if (args.length == 0) {
            System.out.println("Error: No se proporcionó URL");
            return;
        }
        
        wget.parseArguments(args);
        wget.startDownload();
    }
    
    private void showSyntax() {
        System.out.println("========================================================================");
        System.out.println("\t\t=== WGET JAVA ===");
        System.out.println("Sintaxis: wget -r -t 10 --tries 3 --max-depth 10 http://unapagina.io/");
        System.out.println("  donde:");
        System.out.println("    -r           indica uso en modo recursivo");
        System.out.println("    -t <num>     define el tamaño del pool de descarga");
        System.out.println("    --tries <num> indica el número de intentos para descargar el recurso");
        System.out.println("    --max-depth <num> profundidad máxima de recursión (default: 5)");
        System.out.println("========================================================================");
    }
    
    private void parseArguments(String[] args) {
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "-r":
                    recursiveMode = true;
                    break;
                case "-t":
                    if (i + 1 < args.length) {
                        threadPoolSize = Integer.parseInt(args[++i]);
                    }
                    break;
                case "--tries":
                    if (i + 1 < args.length) {
                        maxTries = Integer.parseInt(args[++i]);
                    }
                    break;
                case "--max-depth":
                    if (i + 1 < args.length) {
                        maxDepth = Integer.parseInt(args[++i]);
                    }
                    break;
                default:
                    if (args[i].startsWith("http")) {
                        baseUrl = args[i];
                        parseBaseUrl();
                    }
                    break;
            }
        }
        
        if (baseUrl == null) {
            throw new IllegalArgumentException("No se proporcionó URL válida");
        }
    }
    
    private void parseBaseUrl() {
        try {
            URL url = new URL(baseUrl);
            baseHost = url.getHost();
            basePath = url.getPath();
            if (basePath.isEmpty()) basePath = "/";
        } catch (MalformedURLException e) {
            throw new IllegalArgumentException("URL inválida: " + baseUrl);
        }
    }
    
    private void startDownload() {
        threadPool = Executors.newFixedThreadPool(threadPoolSize);
        downloadSemaphore = new Semaphore(threadPoolSize);
        
        System.out.println("Iniciando descarga de: " + baseUrl);
        System.out.println("Modo recursivo: " + recursiveMode);
        System.out.println("Pool de hilos: " + threadPoolSize);
        System.out.println("Intentos maximos: " + maxTries);
        System.out.println("Profundidad máxima: " + maxDepth);
        System.out.println();
        
        downloadLatch = new CountDownLatch(1);
        
        downloadUrl(baseUrl, 0);
        
        waitForAllDownloads();
        
        threadPool.shutdown();
        try {
            threadPool.awaitTermination(30, TimeUnit.MINUTES);
        } catch (InterruptedException e) {
            System.err.println("Timeout esperando descargas");
        }
        
        printStats();
        createNavigationIndex(); // Añadir esta línea
        
        System.out.println("=====================================");
        System.out.println("\n=== Descarga completada ===");
        System.out.println("URLs descargadas: " + visitedUrls.size());
        System.out.println("\n=====================================\n\n");
    }
    
    private void printStats() {
        System.out.println("\nEstadísticas de descarga:");
        System.out.println("URLs visitadas: " + visitedUrls.size());
        System.out.println("URLs pendientes: " + pendingUrls.size());
        System.out.println("\nTipos de URLs encontradas:");
        
        for (Map.Entry<String, Integer> entry : urlTypes.entrySet()) {
            System.out.println(entry.getKey() + ": " + entry.getValue());
        }
        
        // Imprimir algunas URLs de ejemplo por tipo
        System.out.println("\nEjemplos de URLs por tipo:");
        Map<String, List<String>> urlsByType = new HashMap<>();
        
        for (String url : visitedUrls) {
            String type = getUrlType(url);
            urlsByType.computeIfAbsent(type, k -> new ArrayList<>()).add(url);
        }
        
        for (Map.Entry<String, List<String>> entry : urlsByType.entrySet()) {
            System.out.println("\n" + entry.getKey() + ":");
            int count = 0;
            for (String url : entry.getValue()) {
                if (count++ < 5) { // Mostrar solo los primeros 5 ejemplos
                    System.out.println("  - " + url);
                }
            }
            if (entry.getValue().size() > 5) {
                System.out.println("  ... y " + (entry.getValue().size() - 5) + " más");
            }
        }
    }
    
    private String getUrlType(String url) {
        if (url.contains("/page/") || url.contains("?page=")) return "Página de navegación";
        if (url.matches(".*\\.(css|js)$")) return "Recurso de estilo/script";
        if (url.matches(".*\\.(jpg|jpeg|png|gif|ico|svg|webp)$")) return "Imagen";
        if (url.matches(".*\\.(woff|woff2|ttf|eot)$")) return "Fuente";
        return "Página de contenido";
    }
    
    private void waitForAllDownloads() {
        while (true) {
            try {
                Thread.sleep(1000);
                if (pendingUrls.isEmpty()) {
                    Thread.sleep(2000);
                    if (pendingUrls.isEmpty()) {
                        break;
                    }
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }
    
    private void downloadUrl(String url, int depth) {
        if (depth > maxDepth || visitedUrls.contains(url) || pendingUrls.contains(url)) {
            return;
        }
        
        pendingUrls.add(url);
        
        threadPool.submit(() -> {
            try {
                downloadSemaphore.acquire();
                downloadFile(url, depth);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } finally {
                pendingUrls.remove(url);
                downloadSemaphore.release();
            }
        });
    }
    private void downloadFile(String urlString, int depth) {
        if (visitedUrls.contains(urlString)) {
            return;
        }
        
        visitedUrls.add(urlString);
        String urlType = getUrlType(urlString);
        urlTypes.merge(urlType, 1, Integer::sum);
        
        for (int attempt = 1; attempt <= maxTries; attempt++) {
            try {
                System.out.println("[Hilo-" + Thread.currentThread().getId() + "] " +
                                 "Descargando (intento " + attempt + "): " + urlString);
                
                URL url = new URL(urlString);
                String host = url.getHost();
                int port = url.getPort();
                boolean isHttps = url.getProtocol().equals("https");
                
                if (port == -1) {
                    port = isHttps ? HTTPS_PORT : DEFAULT_PORT;
                }
                
                String path = url.getPath().isEmpty() ? "/" : url.getPath();
                if (url.getQuery() != null) {
                    path += "?" + url.getQuery();
                }
                
                InetAddress address = InetAddress.getByName(host);
                System.out.println("Resolviendo " + host + " -> " + address.getHostAddress());
                
                Socket socket;
                if (isHttps) {
                    socket = createSSLSocket(address, port);
                } else {
                    socket = new Socket(address, port);
                }
                
                socket.setSoTimeout(30000);
                
                OutputStream out = socket.getOutputStream();
                sendHttpRequest(out, host, path);
                
                InputStream in = socket.getInputStream();
                HttpResponse response = readHttpResponseComplete(in);
                
                if (response.statusCode == 301 || response.statusCode == 302 || response.statusCode == 308) {
                    String location = response.location;
                    if (location != null) {
                        System.out.println("↳ Redirigiendo a: " + location + " (código " + response.statusCode + ")");
                        socket.close();
                        
                        String newUrl = resolveUrl(location, urlString);
                        if (newUrl != null && attempt == 1) {
                            visitedUrls.remove(urlString);
                            downloadFile(newUrl, depth);
                            return;
                        }
                    }
                }
                
                if (response.statusCode == 200) {
                    System.out.println("✓ Respuesta 200 OK para: " + urlString);
                    System.out.println("  Content-Length: " + response.contentLength);
                    System.out.println("  Content-Type: " + response.contentType);
                    System.out.println("  Transfer-Encoding: " + response.transferEncoding);
                    System.out.println("  Bytes recibidos: " + response.content.length);
                    
                    // Manejar contenido comprimido
                    if ("gzip".equalsIgnoreCase(response.contentEncoding)) {
                        response.content = decompressGzip(response.content);
                        System.out.println("  Contenido descomprimido: " + response.content.length + " bytes");
                    }
                    
                    String filename = saveFile(urlString, response.content, response.contentType);
                    System.out.println("✓ Archivo guardado: " + filename);
                    
                    if (recursiveMode) {
                        List<String> links = new ArrayList<>();
                        
                        if (isHtmlContent(response.contentType)) {
                            String content = new String(response.content, 
                                                      getCharsetFromContentType(response.contentType));
                            links = extractLinks(content, urlString);
                            String modifiedContent = modifyLinks(content, urlString);
                            
                            Files.write(Paths.get(filename), 
                                      modifiedContent.getBytes(getCharsetFromContentType(response.contentType)));
                            
                            System.out.println("  Enlaces encontrados: " + links.size());
                            
                            for (String link : links) {
                                if (shouldDownloadResource(link, urlString)) {
                                    downloadUrl(link, depth + 1);
                                }
                            }
                        } else if (isCssContent(response.contentType)) {
                            String content = new String(response.content, 
                                                      getCharsetFromContentType(response.contentType));
                            links = extractCssResources(content, urlString);
                            String modifiedContent = modifyCssLinks(content, urlString);
                            
                            Files.write(Paths.get(filename), 
                                      modifiedContent.getBytes(getCharsetFromContentType(response.contentType)));
                            
                            System.out.println("  Recursos CSS encontrados: " + links.size());
                            
                            for (String link : links) {
                                if (shouldDownloadResource(link, urlString)) {
                                    downloadUrl(link, depth + 1);
                                }
                            }
                        }
                    }
                    
                    socket.close();
                    return;
                    
                } else {
                    System.err.println("✗ Error HTTP " + response.statusCode + " para: " + urlString);
                }
                
                socket.close();
                
            } catch (Exception e) {
                System.err.println("✗ Error descargando " + urlString + 
                                 " (intento " + attempt + "): " + e.getMessage());
                if (attempt == maxTries) {
                    System.err.println("✗ Falló descarga después de " + maxTries + 
                                     " intentos: " + urlString);
                }
            }
        }
    }
    
    private byte[] decompressGzip(byte[] compressed) throws IOException {
        try (GZIPInputStream gzipInputStream = 
             new GZIPInputStream(new ByteArrayInputStream(compressed));
             ByteArrayOutputStream resultStream = new ByteArrayOutputStream()) {
            
            byte[] buffer = new byte[8192];
            int length;
            while ((length = gzipInputStream.read(buffer)) != -1) {
                resultStream.write(buffer, 0, length);
            }
            return resultStream.toByteArray();
        }
    }
    
    private Socket createSSLSocket(InetAddress address, int port) throws Exception {
        TrustManager[] trustAllCerts = new TrustManager[] {
            new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() { return null; }
                public void checkClientTrusted(X509Certificate[] certs, String authType) { }
                public void checkServerTrusted(X509Certificate[] certs, String authType) { }
            }
        };
        
        SSLContext sc = SSLContext.getInstance("SSL");
        sc.init(null, trustAllCerts, new java.security.SecureRandom());
        
        SSLSocketFactory factory = sc.getSocketFactory();
        return factory.createSocket(address, port);
    }
    
    private void sendHttpRequest(OutputStream out, String host, String path) throws IOException {
        String request = "GET " + path + " HTTP/1.1\r\n" +
                        "Host: " + host + "\r\n" +
                        "User-Agent: " + USER_AGENT + "\r\n" +
                        "Accept: */*\r\n" +
                        "Accept-Encoding: gzip\r\n" +
                        "Connection: close\r\n" +
                        "\r\n";
        
        out.write(request.getBytes());
        out.flush();
    }
    
    private HttpResponse readHttpResponseComplete(InputStream in) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte[] tempBuffer = new byte[8192];
        int bytesRead;
        
        while ((bytesRead = in.read(tempBuffer)) != -1) {
            buffer.write(tempBuffer, 0, bytesRead);
        }
        
        byte[] allData = buffer.toByteArray();
        
        int headerEnd = findHeaderEnd(allData);
        if (headerEnd == -1) {
            throw new IOException("No se encontró el final de los headers HTTP");
        }
        
        byte[] headerBytes = Arrays.copyOfRange(allData, 0, headerEnd);
        byte[] contentBytes = Arrays.copyOfRange(allData, headerEnd + 4, allData.length);
        
        String headerString = new String(headerBytes, "UTF-8");
        String[] lines = headerString.split("\r?\n");
        
        HttpResponse response = new HttpResponse();
        
        if (lines.length > 0) {
            String statusLine = lines[0];
            System.out.println("Status: " + statusLine);
            String[] parts = statusLine.split(" ");
            if (parts.length >= 2) {
                response.statusCode = Integer.parseInt(parts[1]);
            }
        }
        
        for (int i = 1; i < lines.length; i++) {
            String line = lines[i].trim();
            if (line.isEmpty()) continue;
            
            String[] headerParts = line.split(":", 2);
            if (headerParts.length == 2) {
                String headerName = headerParts[0].trim().toLowerCase();
                String headerValue = headerParts[1].trim();
                
                switch (headerName) {
                    case "content-length":
                        try {
                            response.contentLength = Integer.parseInt(headerValue);
                        } catch (NumberFormatException e) {}
                        break;
                    case "content-type":
                        response.contentType = headerValue;
                        break;
                    case "content-encoding":
                        response.contentEncoding = headerValue;
                        break;
                    case "location":
                        response.location = headerValue;
                        break;
                    case "transfer-encoding":
                        response.transferEncoding = headerValue;
                        break;
                }
            }
        }
        
        if ("chunked".equalsIgnoreCase(response.transferEncoding)) {
            response.content = decodeChunkedContent(contentBytes);
        } else {
            response.content = contentBytes;
        }
        
        return response;
    }
    
    private int findHeaderEnd(byte[] data) {
        for (int i = 0; i < data.length - 3; i++) {
            if (data[i] == '\r' && data[i + 1] == '\n' && 
                data[i + 2] == '\r' && data[i + 3] == '\n') {
                return i;
            }
        }
        return -1;
    }
    
    private byte[] decodeChunkedContent(byte[] chunkedData) throws IOException {
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        ByteArrayInputStream input = new ByteArrayInputStream(chunkedData);
        
        try {
            while (true) {
                String sizeLine = readLine(input);
                if (sizeLine == null || sizeLine.trim().isEmpty()) {
                    break;
                }
                
                int chunkSize;
                try {
                    String sizeStr = sizeLine.split(";")[0].trim();
                    chunkSize = Integer.parseInt(sizeStr, 16);
                } catch (NumberFormatException e) {
                    break;
                }
                
                if (chunkSize == 0) {
                    break;
                }
                
                byte[] chunkData = new byte[chunkSize];
                int totalRead = 0;
                while (totalRead < chunkSize) {
                    int bytesRead = input.read(chunkData, totalRead, chunkSize - totalRead);
                    if (bytesRead == -1) break;
                    totalRead += bytesRead;
                }
                
                result.write(chunkData, 0, totalRead);
                
                readLine(input);
            }
        } catch (Exception e) {
            System.err.println("Error decodificando chunked content: " + e.getMessage());
        }
        
        return result.toByteArray();
    }
    
    private String readLine(ByteArrayInputStream input) {
        StringBuilder line = new StringBuilder();
        int b;
        
        while ((b = input.read()) != -1) {
            if (b == '\r') {
                input.mark(1);
                if (input.read() == '\n') {
                    break;
                } else {
                    input.reset();
                    line.append((char) b);
                }
            } else if (b == '\n') {
                break;
            } else {
                line.append((char) b);
            }
        }
        
        return line.length() == 0 && b == -1 ? null : line.toString();
    }
    
    private String getCharsetFromContentType(String contentType) {
        if (contentType != null && contentType.contains("charset=")) {
            String[] parts = contentType.split("charset=");
            if (parts.length > 1) {
                return parts[1].split(";")[0].trim();
            }
        }
        return "UTF-8";
    }
    
    private String saveFile(String urlString, byte[] content, String contentType) throws IOException {
    URL url = new URL(urlString);
    String path = url.getPath();
    String query = url.getQuery();
    
    // Manejar la página principal y rutas sin extensión
    if (path.isEmpty() || path.equals("/")) {
        path = "/index.html";
    } else if (!path.contains(".")) {
        if (!path.endsWith("/")) {
            path += "/";
        }
        path += "index.html";
    }
    
    // Manejar parámetros de consulta
    if (query != null && !query.isEmpty()) {
        String sanitizedQuery = query.replaceAll("[^a-zA-Z0-9]", "_");
        int extIndex = path.lastIndexOf(".");
        if (extIndex != -1) {
            path = path.substring(0, extIndex) + "_" + sanitizedQuery + 
                  path.substring(extIndex);
        } else {
            path = path + "_" + sanitizedQuery + ".html";
        }
    }
    
    // Crear estructura de directorios
    Path filePath = Paths.get("downloads" + path);
    Files.createDirectories(filePath.getParent());
    
    // Guardar el archivo
    Files.write(filePath, content);
    
    return filePath.toString();
}
    
    private String getExtensionFromContentType(String contentType) {
        if (contentType == null) return ".html";
        
        contentType = contentType.toLowerCase();
        Map<String, String> extensionMap = new HashMap<>();
        extensionMap.put("text/html", ".html");
        extensionMap.put("text/css", ".css");
        extensionMap.put("application/javascript", ".js");
        extensionMap.put("text/javascript", ".js");
        extensionMap.put("image/jpeg", ".jpg");
        extensionMap.put("image/png", ".png");
        extensionMap.put("image/gif", ".gif");
        extensionMap.put("image/svg+xml", ".svg");
        extensionMap.put("image/webp", ".webp");
        extensionMap.put("image/x-icon", ".ico");
        extensionMap.put("image/vnd.microsoft.icon", ".ico");
        extensionMap.put("font/woff", ".woff");
        extensionMap.put("font/woff2", ".woff2");
        extensionMap.put("font/ttf", ".ttf");
        extensionMap.put("application/pdf", ".pdf");
        
        for (Map.Entry<String, String> entry : extensionMap.entrySet()) {
            if (contentType.contains(entry.getKey())) {
                return entry.getValue();
            }
        }
        
        return ".html";
    }
    
    private boolean isHtmlContent(String contentType) {
        return contentType != null && contentType.toLowerCase().contains("text/html");
    }
    
    private boolean isCssContent(String contentType) {
    return contentType != null && 
           (contentType.toLowerCase().contains("text/css") ||
            contentType.toLowerCase().contains("stylesheet"));
}
    
    private List<String> extractLinks(String html, String baseUrl) {
        List<String> links = new ArrayList<>();
        Set<String> uniqueLinks = new HashSet<>();
        
        Map<String, Pattern> patterns = new HashMap<>();
        patterns.put("href", Pattern.compile("<(?:a|link)[^>]*?href=[\"']([^\"']+)[\"'](?:[^>]*?)>", 
                                           Pattern.CASE_INSENSITIVE));
        patterns.put("src", Pattern.compile(
            "<(?:img|script|source|iframe|embed|audio|video)[^>]*?src=[\"']([^\"']+)[\"']", 
            Pattern.CASE_INSENSITIVE));
        patterns.put("srcset", Pattern.compile("<(?:img|source)[^>]*?srcset=[\"']([^\"']+)[\"']", 
                                             Pattern.CASE_INSENSITIVE));
        patterns.put("pagination", Pattern.compile(
            "<(?:a|link)[^>]*?(?:class=[\"'][^\"']*?(?:pagination|page)[^\"']*?[\"'])[^>]*?href=[\"']([^\"']+)[\"']", 
            Pattern.CASE_INSENSITIVE));
        patterns.put("data", Pattern.compile("<object[^>]*?data=[\"']([^\"']+)[\"']", 
                                           Pattern.CASE_INSENSITIVE));
        patterns.put("poster", Pattern.compile("<video[^>]*?poster=[\"']([^\"']+)[\"']", 
                                             Pattern.CASE_INSENSITIVE));
        patterns.put("background", Pattern.compile("<[^>]*?background=[\"']([^\"']+)[\"']", 
                                                 Pattern.CASE_INSENSITIVE));
        patterns.put("css-import", Pattern.compile("@import\\s*[\"']([^\"']+)[\"']", 
                                                 Pattern.CASE_INSENSITIVE));
        patterns.put("css-url", Pattern.compile("url\\([\"']?([^\"')\\s]+)[\"']?\\)", 
                                              Pattern.CASE_INSENSITIVE));
        
        for (Map.Entry<String, Pattern> entry : patterns.entrySet()) {
            Matcher matcher = entry.getValue().matcher(html);
            while (matcher.find()) {
                String link = matcher.group(1).trim();
                
                if (entry.getKey().equals("srcset")) {
                    for (String srcsetUrl : link.split(",")) {
                        String url = srcsetUrl.trim().split("\\s+")[0];
                        processLink(url, baseUrl, uniqueLinks, links);
                    }
                } else {
                    processLink(link, baseUrl, uniqueLinks, links);
                }
            }
        }
        
        return links;
    }
    
    private void processLink(String link, String baseUrl, Set<String> uniqueLinks, List<String> links) {
        if (link.isEmpty()) return;
        
        // Manejar URLs relativas numéricas (común en paginación)
        if (link.matches("\\d+")) {
            link = "./" + link;
        }
        
        String absoluteLink = resolveUrl(link, baseUrl);
        if (absoluteLink != null && !uniqueLinks.contains(absoluteLink)) {
            // Verificar si es una URL de paginación
            if (isPaginationUrl(absoluteLink)) {
                System.out.println("  Encontrado enlace de paginación: " + link + " -> " + absoluteLink);
            }
            uniqueLinks.add(absoluteLink);
            links.add(absoluteLink);
            System.out.println("  Encontrado enlace: " + link + " -> " + absoluteLink);
        }
    }
    
    private boolean isPaginationUrl(String url) {
        return url.matches(".*/(page|p)/\\d+/?.*") ||
               url.matches(".*/\\?page=\\d+.*") ||
               url.matches(".*/page/\\d+/?.*") ||
               url.matches(".*\\?p=\\d+.*");
    }
    
    private List<String> extractCssResources(String css, String baseUrl) {
        List<String> resources = new ArrayList<>();
        Set<String> uniqueResources = new HashSet<>();
        
        Pattern[] patterns = {
            Pattern.compile("@import\\s+[\"']([^\"']+)[\"']", Pattern.CASE_INSENSITIVE),
            Pattern.compile("@import\\s+url\\([\"']?([^\"')]+)[\"']?\\)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("url\\([\"']?([^\"')]+)[\"']?\\)", Pattern.CASE_INSENSITIVE)
        };
        
        for (Pattern pattern : patterns) {
            Matcher matcher = pattern.matcher(css);
            while (matcher.find()) {
                String resource = matcher.group(1);
                String absoluteResource = resolveUrl(resource, baseUrl);
                if (absoluteResource != null && !uniqueResources.contains(absoluteResource)) {
                    uniqueResources.add(absoluteResource);
                    resources.add(absoluteResource);
                }
            }
        }
        
        return resources;
    }
    
    private String modifyLinks(String html, String baseUrl) {
        try {
        URL currentUrl = new URL(baseUrl);
        String currentPath = currentUrl.getPath();
        int depth = currentPath.split("/").length - 1;
        
        Pattern[] patterns = {
            Pattern.compile("(<a[^>]+href=[\"'])([^\"']+)([\"'][^>]*>)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(<img[^>]+src=[\"'])([^\"']+)([\"'][^>]*>)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(<link[^>]+href=[\"'])([^\"']+)([\"'][^>]*>)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(<script[^>]+src=[\"'])([^\"']+)([\"'][^>]*>)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(<source[^>]+src=[\"'])([^\"']+)([\"'][^>]*>)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(@import\\s+[\"'])([^\"']+)([\"'])", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(url\\([\"']?)([^\"')]+)([\"']?\\))", Pattern.CASE_INSENSITIVE)
        };
        
        String result = html;
        
        for (Pattern pattern : patterns) {
            Matcher matcher = pattern.matcher(result);
            StringBuffer sb = new StringBuffer();
            
            while (matcher.find()) {
                String prefix = matcher.group(1);
                String link = matcher.group(2);
                String suffix = matcher.group(3);
                
                String localPath;
                if (link.endsWith(".css")) {
                    // Ajustar rutas CSS según la profundidad
                    String cssPath = link.startsWith("/") ? link : "/" + link;
                    String relPath = "";
                    for (int i = 0; i < depth; i++) {
                        relPath += "../";
                    }
                    localPath = relPath + cssPath.substring(1);
                } else {
                    localPath = convertToLocalPath(link, baseUrl);
                }
                
                matcher.appendReplacement(sb, Matcher.quoteReplacement(prefix + localPath + suffix));
            }
            matcher.appendTail(sb);
            result = sb.toString();
        }
        
        return result;
    } catch (MalformedURLException e) {
        System.err.println("Error modificando enlaces: " + e.getMessage());
        return html;
    }
}
    
private String modifyCssLinks(String css, String baseUrl) {
    Pattern[] patterns = {
        Pattern.compile("(@import\\s+[\"'])([^\"']+)([\"'])", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(@import\\s+url\\([\"']?)([^\"')]+)([\"']?\\))", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(url\\([\"']?)([^\"')]+)([\"']?\\))", Pattern.CASE_INSENSITIVE)
    };
    
    String result = css;
    
    try {
        URL baseUrlObj = new URL(baseUrl);
        String cssPath = baseUrlObj.getPath();
        String cssDir = cssPath.substring(0, cssPath.lastIndexOf('/'));
        
        for (Pattern pattern : patterns) {
            Matcher matcher = pattern.matcher(result);
            StringBuffer sb = new StringBuffer();
            
            while (matcher.find()) {
                String prefix = matcher.group(1);
                String link = matcher.group(2);
                String suffix = matcher.group(3);
                
                // Calcular la ruta relativa desde la ubicación del CSS
                String absoluteLink;
                if (link.startsWith("/")) {
                    // Ruta absoluta desde la raíz
                    absoluteLink = "." + link;
                } else if (link.startsWith("http")) {
                    // URL absoluta, mantener si es del mismo dominio
                    URL linkUrl = new URL(link);
                    if (linkUrl.getHost().equals(baseUrlObj.getHost())) {
                        absoluteLink = "." + linkUrl.getPath();
                    } else {
                        absoluteLink = link; // Mantener URLs externas sin cambios
                    }
                } else {
                    // Ruta relativa al CSS
                    absoluteLink = "../" + link;
                }
                
                matcher.appendReplacement(sb, Matcher.quoteReplacement(prefix + absoluteLink + suffix));
            }
            matcher.appendTail(sb);
            result = sb.toString();
        }
    } catch (MalformedURLException e) {
        System.err.println("Error procesando CSS: " + e.getMessage());
    }
    
    return result;
}
    
    private String resolveUrl(String link, String baseUrl) {
        try {
            if (link == null || link.isEmpty()) return null;
            
            if (link.startsWith("#") || link.startsWith("mailto:") || 
                link.startsWith("javascript:") || link.startsWith("data:")) {
                return null;
            }
            
            URL base = new URL(baseUrl);
            URL resolved = new URL(base, link);
            
            if (!resolved.getHost().equals(base.getHost())) {
                return null;
            }
            
            return resolved.toString();
        } catch (MalformedURLException e) {
            System.err.println("Error resolviendo URL: " + link + " - " + e.getMessage());
            return null;
        }
    }
    
private String convertToLocalPath(String link, String baseUrl) {
    try {
        String absoluteLink = resolveUrl(link, baseUrl);
        if (absoluteLink != null) {
            URL url = new URL(absoluteLink);
            String path = url.getPath();
            String query = url.getQuery();
            
            // Manejar la página principal
            if (path.isEmpty() || path.equals("/")) {
                path = "/index.html";
            } else if (!path.contains(".")) {
                if (!path.endsWith("/")) {
                    path += "/";
                }
                path += "index.html";
            }
            
            // Calcular la profundidad de la página actual
            String currentPath = new URL(baseUrl).getPath();
            int depth = currentPath.split("/").length - 1;
            String prefix = "";
            for (int i = 0; i < depth; i++) {
                prefix += "../";
            }
            
            // Ajustar las rutas relativas según la profundidad
            if (path.startsWith("/")) {
                path = prefix + path.substring(1);
            }
            
            // Manejar los archivos CSS y sus recursos
            if (path.endsWith(".css")) {
                // Mantener la estructura de directorios para CSS
                return prefix + path.substring(1);
            }
            
            // Manejar parámetros de consulta
            if (query != null && !query.isEmpty()) {
                String sanitizedQuery = query.replaceAll("[^a-zA-Z0-9]", "_");
                int extIndex = path.lastIndexOf(".");
                if (extIndex != -1) {
                    path = path.substring(0, extIndex) + "_" + sanitizedQuery + path.substring(extIndex);
                } else {
                    path = path + "_" + sanitizedQuery + ".html";
                }
            }
            
            return path;
        }
    } catch (MalformedURLException e) {
        System.err.println("Error convirtiendo ruta: " + link + " - " + e.getMessage());
    }
    return link;
}
    
    private boolean shouldDownloadResource(String url, String currentUrl) {
        try {
            if (url == null || url.trim().isEmpty()) return false;
            
            String absoluteUrl = resolveUrl(url, currentUrl);
            if (absoluteUrl == null) return false;
            
            URL urlObj = new URL(absoluteUrl);
            
            if (!urlObj.getHost().equals(baseHost)) {
                return false;
            }
            
            if (url.startsWith("#") || url.startsWith("mailto:") || 
                url.startsWith("javascript:") || url.startsWith("data:")) {
                return false;
            }
            
            // Permitir URLs de paginación incluso si ya han sido visitadas
            if (isPaginationUrl(absoluteUrl)) {
                return !pendingUrls.contains(absoluteUrl);
            }
            
            if (visitedUrls.contains(absoluteUrl) || pendingUrls.contains(absoluteUrl)) {
                return false;
            }
            
            return true;
            
        } catch (Exception e) {
            System.err.println("Error evaluando URL: " + url + " - " + e.getMessage());
            return false;
        }
    }
    private void createNavigationIndex() {
    try {
        StringBuilder index = new StringBuilder();
        index.append("<!DOCTYPE html>\n");
        index.append("<html><head><title>Indice de navegacion</title></head>\n");
        index.append("<body>\n");
        index.append("<h1>Indice de paginas descargadas</h1>\n");
        index.append("<ul>\n");
        
        Path downloadsPath = Paths.get("downloads");
        Files.walk(downloadsPath)
             .filter(Files::isRegularFile)
             .sorted()
             .forEach(path -> {
                 String relativePath = downloadsPath.relativize(path).toString();
                 index.append(String.format("<li><a href=\"%s\">%s</a></li>\n", 
                                         relativePath, relativePath));
             });
        
        index.append("</ul></body></html>");
        
        // Guardar el índice
        Files.write(Paths.get("downloads/site_index.html"), 
                   index.toString().getBytes(StandardCharsets.UTF_8));
        
    } catch (IOException e) {
        System.err.println("Error creando índice de navegación: " + e.getMessage());
    }
}
    
    static class HttpResponse {
        int statusCode;
        int contentLength = -1;
        String contentType;
        String contentEncoding;
        String location;
        String transferEncoding;
        byte[] content;
    }
}
