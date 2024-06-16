package org.fupo.javaeasyscan;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

/**
 * @Describe 报告生成
 * @Author novy
 * @Version 1.0
 * @CreateDate 9:33 2024/6/15
 **/
public class ResultUtil {
    private static final Logger logger = LoggerFactory.getLogger(ResultUtil.class);
    public static void generateHtmlReport(List<String> results, String topic) {
        SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMdd");
        String timestamp = sdf.format(new Date());
        String filePath = "audit_report_" + timestamp + ".html";
        boolean fileExists = new File(filePath).exists();

        //防止多次扫描的结果相同导致的重复数据追加，具体实现：往页面里加哈希，然后读取html内容查看是否包含已有的哈希，真是聪明 ≥︺‿︺≤
        String newContentHash = generateHash(results);
        StringBuilder existingContent = new StringBuilder();
        if (fileExists) {
            try {
                List<String> lines = Files.readAllLines(Paths.get(filePath));
                for (String line : lines) {
                    existingContent.append(line).append("\n");
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        if (existingContent.toString().contains(newContentHash)) {
            logger.info("no new content to add, report is latest");
            return;
        }

        try (PrintWriter writer = new PrintWriter(new FileWriter(filePath, true))) {
            if (!fileExists) {
                writer.println("<html>");
                writer.println("<head>");
                writer.println("<title>Fupo JavaEasyScan Result</title>");
                writer.println("<style>");
                writer.println("body { font-family: Arial, sans-serif; margin: 0; padding: 0; background-color: #f4f4f9; color: #333; }");
                writer.println("h1 { text-align: center; color: #333; margin: 20px 0; }");
                writer.println(".navbar { display: flex; justify-content: space-between; align-items: center; background-color: #355678; padding: 10px; text-align: center; border-radius: 0; margin-bottom: 20px; position: sticky; top: 0; z-index: 1000; transition: background-color 0.3s; }");
                writer.println(".navbar-logo { color: white; font-size: 24px; font-weight: bold; }");
                writer.println(".navbar-menu { display: flex; }");
                writer.println(".navbar a { color: white; text-decoration: none; font-size: 18px; margin: 0 15px; position: relative; }");
                writer.println(".modal { display: none; position: fixed; z-index: 1000; left: 50%; top: 50%; width: 300px; padding: 20px; background: white; border: 1px solid #ccc; border-radius: 10px; transform: translate(-50%, -50%); box-shadow: 0 0 10px rgba(0, 0, 0, 0.5); }");
                writer.println(".modal-header { font-size: 18px; font-weight: bold; margin-bottom: 10px; }");
                writer.println(".modal-content { font-size: 14px; margin-bottom: 20px; }");
                writer.println(".modal-close { background: #355678; color: white; border: none; padding: 5px 10px; cursor: pointer; border-radius: 5px; }");
                writer.println(".container { margin: 20px auto; padding: 0 20px; max-width: 800px; border-radius: 8px; }");
                writer.println(".title { font-size: 18px; font-weight: bold; cursor: pointer; padding: 10px; background: #355678; color: white; border-radius: 8px 8px 0 0; display: flex; justify-content: space-between; align-items: center; }");
                writer.println(".content { display: none; padding: 10px; border: 1px solid #ddd; border-top: none; border-radius: 0 0 8px 8px; background: white; }");
                writer.println(".content p { margin: 0; white-space: pre-wrap; }");
                writer.println(".arrow { font-size: 12px; margin-left: 10px; transition: transform 0.2s; }");
                writer.println(".title:hover { background: #0056b3; }");
                writer.println("</style>");
                writer.println("</head>");
                writer.println("<body>");
                writer.println("<div class='navbar'><div class='navbar-logo'>Fupo JavaEasyScanner</div><div class='navbar-menu'><a href='https://novysodope.github.io/'>Home</a><a href='https://github.com/novysodope'>Github</a><a href='https://github.com/novysodope/javaeasyscan' id='about-link'>About</a></div></div>");
                writer.println("<h1>Detailed report</h1>");
                writer.println("<div class='modal' id='about-modal'><div class='modal-header'>关于富婆</div><div class='modal-content'>有关本工具的更多信息请移步到Github，如果可以，还可以顺便star一下，后续还会更新漏洞审计和优化分析流程</div><button class='modal-close'>Close</button></div>");
            }

            for (int i = 0; i < results.size(); i++) {
                writer.println("<div class='container'>");
                writer.printf("<div class='title'>%s %d <span class='arrow'>&#9654;</span></div>%n", topic, i + 1);
                writer.println("<div class='content'>");
                writer.printf("<p>%s</p>%n", results.get(i).replace("\n", "<br>"));
                writer.println("</div>");
                writer.println("</div>");
            }

            if (!fileExists) {
                writer.println("<script>");
                writer.println("document.addEventListener('DOMContentLoaded', function() {");
                writer.println("    var navbar = document.querySelector('.navbar');");
                writer.println("    var aboutLink = document.getElementById('about-link');");
                writer.println("    var aboutModal = document.getElementById('about-modal');");
                writer.println("    var closeModal = document.querySelector('.modal-close');");
                writer.println("    aboutLink.addEventListener('click', function(event) {");
                writer.println("        event.preventDefault();");
                writer.println("        aboutModal.style.display = 'block';");
                writer.println("    });");
                writer.println("    closeModal.addEventListener('click', function() {");
                writer.println("        aboutModal.style.display = 'none';");
                writer.println("    });");
                writer.println("    window.addEventListener('scroll', function() {");
                writer.println("        if (window.scrollY > 50) {");
                writer.println("            navbar.style.backgroundColor = 'rgba(53, 86, 120, 0.5)';");
                writer.println("        } else {");
                writer.println("            navbar.style.backgroundColor = '#355678';");
                writer.println("        }");
                writer.println("    });");
                writer.println("    document.querySelectorAll('.title').forEach(title => {");
                writer.println("        title.addEventListener('click', () => {");
                writer.println("            const content = title.nextElementSibling;");
                writer.println("            const arrow = title.querySelector('.arrow');");
                writer.println("            if (content.style.display === 'block') {");
                writer.println("                content.style.display = 'none';");
                writer.println("                arrow.innerHTML = '&#9654;';");
                writer.println("                arrow.style.transform = 'rotate(0deg)';");
                writer.println("            } else {");
                writer.println("                content.style.display = 'block';");
                writer.println("                arrow.innerHTML = '&#9660;';");
                writer.println("                arrow.style.transform = 'rotate(90deg)';");
                writer.println("            }");
                writer.println("        });");
                writer.println("    });");
                writer.println("});");
                writer.println("</script>");
                writer.println("</body>");
                writer.println("</html>");
            }
            writer.println("<!-- report hash: " + newContentHash + " -->");
            logger.info("create report: " + filePath);
        } catch (IOException e) {
            e.printStackTrace();
        }


    }

    private static String generateHash(List<String> content) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            String concatenatedContent = content.stream().collect(Collectors.joining());
            byte[] hash = digest.digest(concatenatedContent.getBytes());
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Error generating hash", e);
        }
    }
}
