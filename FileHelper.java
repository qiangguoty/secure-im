import java.nio.ByteBuffer;
import java.io.*;

public class FileHelper {
    public static void writeBytes(byte[] bytes, String path) throws IOException {
    /*
    Write the byte array to file.
     */
        FileOutputStream fos = null;
        File file = new File(path);
        try {
            fos = new FileOutputStream(file);
            fos.write(bytes);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        finally {
            if (fos != null) {
                fos.close();
            }
        }
    }

    public static byte[] readBytes(String path) {
    /*
    Read and convert file into byte array.
     */
        FileInputStream fileInputStream;
        File file = new File(path);
        byte[] bytes = new byte[(int)file.length()];

        try {
            fileInputStream = new FileInputStream(file);
            fileInputStream.read(bytes);
            fileInputStream.close();
        }catch(Exception e){
            e.printStackTrace();
        } finally {
        }
        return bytes;
    }
}