
import java.lang.String;
import java.util.HashMap;

class TestDB {
    public static void main(String[] args) {
        try {
            // init cipher
            AESCipher cipher = new AESCipher();
            cipher.generateKey(new String("123456").getBytes());

            // write DB
            /*
            ServerDBHelper.resetDB(cipher);
            System.out.println("test.db created");
            */

            // read DB
            HashMap<String, String> db = new HashMap<String, String>();
            db = ServerDBHelper.readDB(cipher);
            if (db != null) {
                System.out.println("test.db readed into mem");
            }
          
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
