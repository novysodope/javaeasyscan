package org.fupo.javaeasyscan;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;

/**
 * @Describe
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

        try (PrintWriter writer = new PrintWriter(new FileWriter(filePath, true))) { // enable append mode
            if (!fileExists) {
                writer.println("<html>");
                writer.println("<head>");
                writer.println("<title>Fupo JavaEasyScan Result</title>");
                writer.println("<style>");
                writer.println("body { font-family: Arial, sans-serif; margin: 40px; }");
                writer.println("h1 { text-align: center; color: #333; }");
                writer.println(".container { margin-bottom: 20px; }");
                writer.println(".title { font-size: 18px; font-weight: bold; cursor: pointer; padding: 10px; background: #eee; border: 1px solid #ddd; border-radius: 4px; display: flex; justify-content: space-between; align-items: center; }");
                writer.println(".content { display: none; padding: 10px; border: 1px solid #ddd; border-top: none; border-radius: 0 0 4px 4px; }");
                writer.println(".content p { margin: 0; white-space: pre-wrap; }");
                writer.println(".arrow { font-size: 12px; margin-left: 10px; }");
                writer.println("</style>");
                writer.println("</head>");
                writer.println("<body>");
                writer.println("<h1>Fupo JavaEasyScan CodeAudit Report</h1>");
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
                writer.println("document.querySelectorAll('.title').forEach(title => {");
                writer.println("    title.addEventListener('click', () => {");
                writer.println("        const content = title.nextElementSibling;");
                writer.println("        const arrow = title.querySelector('.arrow');");
                writer.println("        if (content.style.display === 'block') {");
                writer.println("            content.style.display = 'none';");
                writer.println("            arrow.innerHTML = '&#9654;';");
                writer.println("        } else {");
                writer.println("            content.style.display = 'block';");
                writer.println("            arrow.innerHTML = '&#9660;';");
                writer.println("        }");
                writer.println("    });");
                writer.println("});");
                writer.println("});");
                writer.println("</script>");
                writer.println("</body>");
                writer.println("</html>");
            }

            logger.info("create report: " + filePath);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

}
