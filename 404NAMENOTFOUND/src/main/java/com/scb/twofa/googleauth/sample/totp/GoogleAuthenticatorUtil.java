package com.scb.twofa.googleauth.sample.totp;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Date;
import java.util.EnumMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.MultiFormatWriter;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel;
import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorConfig;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;

public class GoogleAuthenticatorUtil {

	private long KEY_VALIDATION_INTERVAL_MS = TimeUnit.SECONDS.toMillis(30);
	
	final GoogleAuthenticator gAuth = new GoogleAuthenticator();	
	final GoogleAuthenticatorKey googleAuthkey = gAuth.createCredentials();
	GoogleAuthenticatorConfig config = new GoogleAuthenticatorConfig();
	String key = googleAuthkey.getKey();
	static String qrCodeLocation = "C:/Users/1591046/Desktop/QRCode";
	
	
	int lastUsedPassword = -1; // last successfully used password
    private long lastVerifiedTime = 0; // time of last success

	
	private static String generateKeyUri(String account, String issuer,
            String secret) throws URISyntaxException {

        URI uri = new URI("otpauth", "totp", "/" + issuer + ":" + account,
                "secret=" + secret + "&issuer=" + issuer, null);

        return uri.toASCIIString();
    }
	
	public static byte[] getQRCodeImage(String text, int width, int height) {
		try {
			QRCodeWriter qrCodeWriter = new QRCodeWriter();
			BitMatrix bitMatrix = qrCodeWriter.encode(text, BarcodeFormat.QR_CODE, width, height);
			ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
			MatrixToImageWriter.writeToStream(bitMatrix, "png", byteArrayOutputStream);
			return byteArrayOutputStream.toByteArray();
		} catch (Exception e) {
			return null;
		}
	}

	public byte[] generateQRCode(String id, String emailId, String secret) throws URISyntaxException, WriterException, IOException {
		String filePath = qrCodeLocation + File.separator + id + ".png";
		String charset = "UTF-8"; // or "ISO-8859-1"
		Map<EncodeHintType, ErrorCorrectionLevel> hintMap = new EnumMap<>(EncodeHintType.class);
		hintMap.put(EncodeHintType.ERROR_CORRECTION, ErrorCorrectionLevel.L);
		String qrCodeData = generateKeyUri("sc.com", emailId, key);;
		return createQRCode(qrCodeData, filePath, charset, hintMap, 200, 200);
	}
	
	public static byte[] generateQRCode(String emailId, String secret) throws URISyntaxException, WriterException, IOException {
		
		String charset = "UTF-8"; // or "ISO-8859-1"
		Map<EncodeHintType, ErrorCorrectionLevel> hintMap = new EnumMap<>(EncodeHintType.class);
		hintMap.put(EncodeHintType.ERROR_CORRECTION, ErrorCorrectionLevel.L);
		String qrCodeData = generateKeyUri(emailId,"standardchartered.com", secret);;
		return createQRCode(qrCodeData, charset, hintMap, 200, 200);
	}
	

	private static byte[] createQRCode(String qrCodeData, String filePath, String charset,
			@SuppressWarnings("rawtypes") Map hintMap, int qrCodeheight, int qrCodewidth)
			throws WriterException, IOException {
		@SuppressWarnings("unchecked")
		BitMatrix matrix = new MultiFormatWriter().encode(new String(qrCodeData.getBytes(charset), charset),
				BarcodeFormat.QR_CODE, qrCodewidth, qrCodeheight, hintMap);
		File file = new File(filePath);
		MatrixToImageWriter.writeToPath(matrix, filePath.substring(filePath.lastIndexOf('.') + 1), file.toPath());
		
		ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
		MatrixToImageWriter.writeToStream(matrix, "png", byteArrayOutputStream);
		return byteArrayOutputStream.toByteArray();
	}
	
	
	private static byte[] createQRCode(String qrCodeData, String charset,
			@SuppressWarnings("rawtypes") Map hintMap, int qrCodeheight, int qrCodewidth)
			throws WriterException, IOException {
		@SuppressWarnings("unchecked")
		BitMatrix matrix = new MultiFormatWriter().encode(new String(qrCodeData.getBytes(charset), charset),
				BarcodeFormat.QR_CODE, qrCodewidth, qrCodeheight, hintMap);
		
		ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
		MatrixToImageWriter.writeToStream(matrix, "png", byteArrayOutputStream);
		return byteArrayOutputStream.toByteArray();
	}

	public boolean performAuthentication(String value, String secret) {
		Integer totp = Integer.valueOf((value.equals("") ? "-1" : value));
		boolean unused = isUnusedPassword(totp, config.getWindowSize());
		System.out.println("unused = "+unused);
		boolean matches = gAuth.authorize(secret, totp);
		System.out.println("matches = "+matches);
		return (unused && matches);
	}

	private boolean isUnusedPassword(int password, int windowSize) {
		long now = new Date().getTime();
		long timeslotNow = now / KEY_VALIDATION_INTERVAL_MS;
		int forwardTimeslots = ((windowSize - 1) / 2);
		long timeslotThen = lastVerifiedTime / KEY_VALIDATION_INTERVAL_MS;
		if (password != lastUsedPassword || timeslotNow > timeslotThen + forwardTimeslots) {
			lastUsedPassword = password;
			lastVerifiedTime = now;
			return true;
		}
		return false;
	}

}
