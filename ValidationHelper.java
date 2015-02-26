class ValidationHelper {
    public static final int timeDelta = 5000;   // 5000 ms
    public static boolean validateTimestamp(long ts) {
        long current = System.currentTimeMillis();
        if (Math.abs(current - ts) > timeDelta) {
            return false;
        }
        return true;
    }

    public static long getCurrentTimestamp() {
        return System.currentTimeMillis();
    }
}