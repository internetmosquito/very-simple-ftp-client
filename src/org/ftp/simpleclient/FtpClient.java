package org.ftp.simpleclient;

import java.io.File;
import java.io.FileFilter;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Iterator;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.log4j.Logger;

import it.sauronsoftware.ftp4j.FTPAbortedException;
import it.sauronsoftware.ftp4j.FTPClient;
import it.sauronsoftware.ftp4j.FTPDataTransferException;
import it.sauronsoftware.ftp4j.FTPException;
import it.sauronsoftware.ftp4j.FTPFile;
import it.sauronsoftware.ftp4j.FTPIllegalReplyException;
import it.sauronsoftware.ftp4j.FTPListParseException;

/**
 * @author Alejandro Villamarin
 * @version 1.0.0
 * 
 * Basic functionalities of a very simple ftp client using ftp4j library
 * 
 */
public class FtpClient {
	
	/**
	 * A logger object 
	 */
	private static Logger logger;
	/**
	 * FTPClient object
	 */
	private FTPClient client;
	
	/**
	 * An array of TrustManager objects, used when bypassing SSL cert is required
	 */
	TrustManager[] trustManager;
	/**
	 * A SSLContext object, only required when bypass is TRUE
	 */
	SSLContext sslContext;
	/**
	 * Enum type for the type of secure connection, possible values are
	 * FTP - The default value
	 * FTPS - FTPS protocol, implicit SSL 
	 * FTPES - FTPES protocol, explicit SSL 
	 */
	public enum secure{FTP, FTPS, FTPES}
	private secure connectionType; 

	/**
	 * FTP server address
	 */
	private String host;
	/**
	 * A list used when listing directories
	 */
	private FTPFile[] list;
	/**
	 * FTP listening port
	 */
	private int port;
	/**
	 * FTP user
	 */
	private String user;
	/**
	 * FTP user password
	 */
	private String password;
	/**
	 * Bypass SSL certificate checking flag, only to be used if your FTP server does not have a CA signed certificate and adding it to your keystore does not work
	 */
	private boolean bypass;
	/**
	 * Bypass SSL certificate checking flag, only to be used if your FTP server does not have a CA signed certificate and adding it to your keystore does not work
	 */
	private SSLSocketFactory sslSocketFactory;
	/**
	 * Flag to indicate whether the FTPClient field is set up
	 */
	private boolean setup;
	/**
	 * Flag to indicate whether connection is established or not
	 */
	private boolean connected;
	/**
	 * Flag to indicate whether the client is logged in
	 */
	private boolean logged;
	
	/**
	 * Constructor, sets up all the required fields with default values
	 * 
	 */
	public FtpClient(){
		
		FtpClient.logger = Logger.getLogger(FtpClient.class);
		//set FTP as default connectionType
		this.connectionType = secure.FTP;
		this.bypass = false;
		this.connected = false;
		this.setup = false;
		this.logged = false;
		this.list = null;
		
	}
	
	/**
	 * Constructor initializes fields with given parameters
	 * 
	 * @param	host		The FTP host address
	 * @param	port		The FTP listening port
	 * @param	user		The FTP user name
	 * @param	password	The user's password
	 * @param   connType	A connection type where 0 is FTP, 1 is FTPS and 2 is FTPES
	 * @param	flag		If true, no SSL certificate checking will be performed (NOT RECOMMENDED)
	 * 
	 */
	public FtpClient(String host, int port, String user, String password, secure connType, boolean flag){
		
		FtpClient.logger = Logger.getLogger(FtpClient.class);
		this.host = host;
		this.port = port;
		this.user = user;
		this.password = password;
		this.connectionType = connType;
		this.bypass = flag;
		this.connected = false;
		this.setup = false;
		this.logged = false;
			
	}
	
	/**
	 * Initializes the FTPclient field and the rest of associated fields required 
	 * Also it prepares the client for bypassing the SSL certificate checking procedure
	 * if required
	 * 
	 * @return	True if everything was set up correctly
	 */
	public boolean setupClient(){
		
		//initialize the FTPClient object
		this.client = new FTPClient();
		//Set connection type
		if (this.connectionType == secure.FTP){
			client.setSecurity(FTPClient.SECURITY_FTP);
		}
		else{
			if (this.connectionType == secure.FTPS){
				client.setSecurity(FTPClient.SECURITY_FTPS);
			}
			else{
				if (this.connectionType == secure.FTPES){
					client.setSecurity(FTPClient.SECURITY_FTPES);
				}
			}
		}
		
		
		//check if we need to bypass the SSL cert
		if (this.bypass){
			//Declare our own X509 trust manager 
			this.trustManager = new TrustManager[] {
					//Initialize the array with our own implementation of the X509TrustManager
					new X509TrustManager() {
						
						public X509Certificate[] getAcceptedIssuers() {
							return null;
						}
						public void checkClientTrusted(X509Certificate[] certs, String authType) {
							
						}
						/* This is the method that really checks the certitficate */
						public void checkServerTrusted(X509Certificate[] certs, String authType) {
							logger.info("Bypassing X509 SSL cert procedure, don't do this at home.");
						}
			} };
			
			try {
				
				//initialize SSL context
				sslContext = SSLContext.getInstance("SSL");
				sslContext.init(null, trustManager, new SecureRandom());
				sslSocketFactory = sslContext.getSocketFactory();
				client.setSSLSocketFactory(sslSocketFactory);
				this.setup = true;
				logger.info("FTPClient setup completed successfully.");
				return true;
			} 
			catch (NoSuchAlgorithmException e) {
				logger.error("SSL was not found as algorithm");
				e.printStackTrace();
				this.setup = false;
				return false;
			} 
			catch (KeyManagementException e) {
				logger.error("There was a problem with the key manager");
				e.printStackTrace();
				this.setup = false;
				return false;
			}
		}
		this.setup = true;
		System.out.println("INFO: FTPClient setup completed successfully.");
		return true;
	}
	
	/**
	 * Connects the FTPClient object to the FTP server specified in the constructor
	 * 
	 * @return	True if connection was successfully established  
	 */
	public boolean connect(){
		
		//check that we have the required elements to establish a connection
		if (!this.host.isEmpty() && this.port != 0 && !this.user.isEmpty() && !this.password.isEmpty()){
			try {
				//Check if we are connected
				if (this.setup){
					this.client.connect(this.host, this.port);
					System.out.println("INFO: Connection with server " + this.host + " at " + this.port + " established correctly");
					this.connected = true;
					logger.info("FTPClient connection completed successfully.");
					return true;
				}
				else{
					logger.error("FTPclient field must be set up before connecting. Use setupClient method first.");
					return false;
				}
				
			} catch (IllegalStateException e) {	
				logger.error("Could not connect to the FTP server. Aborting");
				e.printStackTrace();	
			} 
			catch (IOException e) {
				logger.error("Could not connect to the FTP server. Aborting");
				e.printStackTrace();
			} 
			catch (FTPIllegalReplyException e) {
				logger.error("Could not connect to the FTP server. Aborting");
				e.printStackTrace();
			} 
			catch (FTPException e) {
				logger.error("Could not connect to the FTP server. Aborting");
				e.printStackTrace();
			}
		}
		else{
			logger.error("Some of the required fields for connecting to the FTP server are empty or invalid. Connection aborted.");
			return false;
		}
		return false;
		
	}
	
	
	/**
	 * Disconnects the FTPClient object from the FTP server specified in the constructor
	 * 
	 * @return	True if connection was successfully terminated  
	 */
	public boolean disconnect(){
		
		
		try {
			//Check if we are connected
			if (this.connected){
				this.client.disconnect(true);
				logger.info("Disconnection from server " + this.host + " at " + this.port + " terminated correctly");
				this.connected = false;
				logger.info("FTPClient disconnected successfully.");
				return true;
			}
			else{
				logger.error("FTPclient is not connected, no need to disconnect.");
				return false;
			}
				
		} 
		catch (IllegalStateException e) {
			logger.error("Could not disconnect from server " + this.host);
			e.printStackTrace();
			return false;
		}
		catch (IOException e) {
			logger.error("Could not disconnect from server " + this.host);
			e.printStackTrace();
			return false;
		}
		catch (FTPIllegalReplyException e) {
			logger.error("Could not disconnect from server " + this.host);
			e.printStackTrace();
			return false;
		}
		catch (FTPException e) {
			logger.error("Could not disconnect from server " + this.host);
			e.printStackTrace();
			return false;
		}
		
	}
	
	/**
	 * Logs in the FTP server with the user/pass provided in the FtpClient constructor
	 * 
	 * @return	True if logging process was successful  
	 */
	public boolean login(){
		
		//check that we have the required elements to establish a connection
		if (!this.user.isEmpty() && !this.password.isEmpty()){

			try {
				if (this.connected){
					this.client.login(this.user, this.password);
					logger.info("Logged in server " + this.host + " at " + this.port + " successfully");
					this.logged = true;
					logger.info("FTPClient login completed successfully.");
					return true;
				}
				else{
					logger.error("You cannot join if disconnected, please use connect method prior login.");
					return false;
				}
				
			} 
			catch (IllegalStateException e) {
				logger.error("There was an error trying to login to the server. Aborting");
				e.printStackTrace();
			}
			catch (IOException e) {
				logger.error("There was an error trying to login to the server. Aborting");
				e.printStackTrace();
			}
			catch (FTPIllegalReplyException e) {
				logger.error("There was an error trying to login to the server. Aborting");
				e.printStackTrace();
			} 
			catch (FTPException e) {
				logger.error("There was an error trying to login to the server. Aborting");
				e.printStackTrace();
			}
		}
		else{
			logger.error("Either the user or the password provided are empty, making logging not feasible.");
			this.logged = false;
			return false;
		}
		this.logged = false;
		return false;
		
	}
	
	
	/**
	 * Uploads the set of files within the source directory to the destination directory
	 * 
	 * @param	sourceDir	The source directory where the files are located
	 * 
	 * @param	destDir		The destination directory where the files will be placed
	 * 
	 * @return	TRUE if the upload was successful
	 * 
	 */
	public boolean uploadDirFiles(String sourceDir, String destDir){
		
		//check that given params are not empty
		if (sourceDir.isEmpty() || destDir.isEmpty()){
			logger.error("Some of the given parameters are void. Uploading aborted...");
			return false;
		}
		else{
			
			//check logged state
			if (this.logged){
				
				//get the files names to transfer
				ArrayList<String> names = getFileNames(sourceDir);
				
				if (!names.isEmpty()){
					
					//change to destination directory in ftp
					try {
						String dir = client.currentDirectory();
						logger.info("Current directory is " + dir);
						
						//change directory only if necessary
						if (!this.checkSameFolder(dir, destDir)){
							logger.info("Changing directory to  " + destDir);
							client.changeDirectory(destDir);
							logger.info("Directory changed successfully, proceding to upload");
						}
					
						Iterator<String> iterator = names.iterator();
						//For each file encountered, create a fullpath and upload it
						while (iterator.hasNext()){
							
							//get the filename
							String name = iterator.next();
							String path = sourceDir + "/" + name;
							File file = new File(path);
							this.client.upload(file);
							logger.info("File " + name  + " uploaded successfully!");
						}
						
						logger.info("All files uploaded successfully to " + destDir );
						return true;
						
					} 
					catch (IllegalStateException e) {
						logger.error("Could not upload file to " + destDir + " OR could not change directory to " + destDir);
						e.printStackTrace();
						return false;
					} 
					catch (IOException e) {
						logger.error("Could not upload file to " + destDir + " OR could not change directory to " + destDir);
						e.printStackTrace();
						return false;
					} 
					catch (FTPIllegalReplyException e) {
						logger.error("Could not upload file to " + destDir + " OR could not change directory to " + destDir);
						e.printStackTrace();
						return false;
					} 
					catch (FTPException e) {
						logger.error("Could not upload file to " + destDir + " OR could not change directory to " + destDir);
						e.printStackTrace();
						return false;
					}
					catch (FTPDataTransferException e) {
						logger.error("Could not upload file to " + destDir);
						e.printStackTrace();
						return false;
					} 
					catch (FTPAbortedException e) {
						logger.error("Could not upload file to " + destDir);
						e.printStackTrace();
						return false;							
					}
				}
			}	
			else{
				logger.error("You can not send files if you are not logged in. Use login method first.");
				return false;
			}
			
		}
		
		return false;
	}
	
	/**
	 * Upload the specified file to the destination directory
	 * 
	 * @param	filepath	The name of the file to upload, path + name
	 * 
	 * @param	destDir		The destination directory where the file will be placed
	 * 
	 * @return	TRUE if the upload was successful
	 * 
	 */
	public boolean uploadFile(String filepath, String destDir){
		
		//check that given params are not empty
		if (filepath.isEmpty() || destDir.isEmpty()){
			logger.error("Some of the given parameters are void. Uploading aborted...");
			return false;
		}
		else{
			
			//check logged state
			if (this.logged){
						
				File file = new File(filepath);
				//change to destination directory in ftp
				try {
					
					String dir = client.currentDirectory();
					
					//change directory only if necessary
					if (!this.checkSameFolder(dir, destDir)){
						logger.info("Changing directory to  " + destDir);
						client.changeDirectory(destDir);
						logger.info("Directory changed successfully, proceding to upload");
					}

					//check that file really exists
					if (file.exists()){
				
							this.client.upload(file);
							logger.info("File " + file.getName()  + " uploaded successfully!");
							return true;
							
					}
					//specified file does not exist, aborting
					else{
						
						logger.error("Specified file " + filepath + " does not exist. Aborting upload.");
						return false;
					}
				}
				catch (FTPDataTransferException e) {
					logger.error("Could not upload file " + file.getName() + " to " + destDir);
					e.printStackTrace();
					return false;
				} 
				catch (FTPAbortedException e) {
					logger.error("Could not upload file " + file.getName() + " to " + destDir);
					e.printStackTrace();
					return false;							
				}
				catch (IllegalStateException e) {
					logger.error("Could not change directory to: " + destDir + " or could not upload file " + file);
					e.printStackTrace();
					return false;
				} 
				catch (IOException e) {	
					logger.error("Could not change directory to: " + destDir + " or could not upload file " + file);
					e.printStackTrace();
					return false;
				} 
				catch (FTPIllegalReplyException e) {	
					logger.error("Could not change directory to: " + destDir + " or could not upload file " + file);
					e.printStackTrace();
					return false;
				} 
				catch (FTPException e) {
					logger.error("Could not change directory to: " + destDir + " or could not upload file " + file);
					e.printStackTrace();
					return false;
				}
			}
			else{
				logger.error("You can not send files if you are not logged in. Use login method first.");
				return false;
			}
		}
	}
	
	
	/**
	 * Downloads the specified file to the destination directory
	 * 
	 * @param	file			The name of the file to download, just the name no path required
	 * 
	 * @param	sourceDir		The path where the file is located in the FTP server
	 * 
	 * @param	destDir			The local path where the file will be saved 
	 * 
	 * @return	TRUE if the download was successful
	 * 
	 */
	public boolean downloadFile(String file, String sourceDir, String destDir){
		
		//check that given params are not empty
		if (file.isEmpty() || destDir.isEmpty() || sourceDir.isEmpty()){
			logger.error("Some of the given parameters are void. Downloading aborted...");
			return false;
		}
		else{
			
			//check logged state
			if (this.logged){
						
				//change to destination directory in ftp
				try {
					
					String dir = client.currentDirectory();
					
					//change directory only if necessary
					if (!this.checkSameFolder(dir,sourceDir)){
						logger.info("Current directory is " + dir);
						logger.info("Changing directory to  " + sourceDir);
						client.changeDirectory(sourceDir);
						logger.info("Directory changed successfully, proceding to download");
					}
					
					String localFilePath = new String();
					
					//Check that specified destination Dir exists
					File destDirectory = new File(destDir);
					
					//check that local destination exists and truly is a directory
					if (destDirectory.exists() && destDirectory.isDirectory()){
					
						//check for trailing slash when constructing full path + file name
						if (!destDir.endsWith("/")){
							//add the last trailing slash
							localFilePath = destDir + file;
						}
						else{
							localFilePath = destDir + "/" + file;
						}
						
						File localFile = new File(localFilePath);
												
						this.client.download(file, localFile);
						logger.info("File " + file  + " downloaded successfully to " + destDir);
								
						return true;
						
					}
					else{
						logger.error("Specified destination folder does not exist or is not a folder. Aborting download.");
						return false;
					}
				}
				catch (FTPDataTransferException e) {
					logger.error("Could not download file " + file + " to " + destDir);
					e.printStackTrace();
					return false;
				} 
				catch (FTPAbortedException e) {
					logger.error("Could not download file " + file + " to " + destDir);
					e.printStackTrace();
					return false;							
				}
				
				catch (IllegalStateException e) {
					logger.error("Could not change directory to: " + sourceDir + " or could not download file " + file);
					e.printStackTrace();
					return false;
				} 
				catch (IOException e) {	
					logger.error("Could not change directory to: " + sourceDir + " or could not download file " + file);
					e.printStackTrace();
					return false;
				} 
				catch (FTPIllegalReplyException e) {	
					logger.error("Could not change directory to: " + sourceDir + " or could not download file " + file);
					e.printStackTrace();
					return false;
				} 
				catch (FTPException e) {
					logger.error("Could not change directory to: " + sourceDir + " or could not download file " + file);
					e.printStackTrace();
					return false;
				}
			}
			else{
				logger.error("You can not send files if you are not logged in. Use login method first.");
				return false;
			}
		}
	}
	
	/**
	 * Downloads the set of files within the source directory to the destination directory
	 * 
	 * @param	sourceDir			The source directory where the files are located
	 * 
	 * @param	destDir		The destination directory where the files will be placed
	 * 
	 * @return	<code>true</code> if the upload was successful
	 * 
	 */
	public boolean downloadDirFiles(String sourceDir, String destDir){
		
		//check that given params are not empty
		if (sourceDir.isEmpty() && destDir.isEmpty()){
			logger.error("Some of the given parameters are void. Downloading aborted...");
			return false;
		}
		else{
			
			//check logged state
			if (this.logged){
				
				//change directory
				try {
				
					String dir = client.currentDirectory();
					
					//change directory only if necessary
					if (!this.checkSameFolder(dir, sourceDir)){
						logger.info("Current directory is " + dir);
						logger.info("Changing directory to  " + sourceDir);
						client.changeDirectory(sourceDir);
						logger.info("Directory changed successfully, proceding to download");
					}
					
					//list files in source directory	
					Object o = Class.forName("it.sauronsoftware.ftp4j.FTPFile");
					logger.info("Instantiated FTPFile " + o.toString() + " list correctly. Gathering list of files");
					list = client.list();
					
					//check that there was something in the folder specified
					if (list.length!=0){
						//download each file
						for (int i=0; i<list.length; i++){	
							//check that we have a file
							if (list[i].getType()==FTPFile.TYPE_FILE){
								//get the filename
								String name = list[i].getName();
								String path = destDir + "/" + name;
								File file = new File(path);
								//Download file
								this.client.download(name, file);
								logger.info("File " + name  + " downloaded successfully!");
							}
						}
						
						logger.info("All files downloaded successfully to " + destDir );
						return true;
					}
					//if there were no files, abort download
					else{
						logger.error("There were no files in the given directory. Aborting download");
						return false;
					}
				} 
				catch (IllegalStateException e1) {
					logger.error("Listing for files, changing directory to " + sourceDir + " or downloading a file went wrong. Aborting Download");
					e1.printStackTrace();
					return false;
				} 
				catch (IOException e1) {
					logger.error("Listing for files, changing directory to " + sourceDir + " or downloading a file went wrong. Aborting Download");
					e1.printStackTrace();
					return false;
				} 
				catch (FTPIllegalReplyException e1) {
					logger.error("Listing for files, changing directory to " + sourceDir + " or downloading a file went wrong. Aborting Download");
					e1.printStackTrace();
					return false;
				} 
				catch (FTPException e1) {
					logger.error("Listing for files, changing directory to " + sourceDir + " or downloading a file went wrong. Aborting Download");
					e1.printStackTrace();
					return false;
				} 
				catch (FTPDataTransferException e1) {
					logger.error("Listing for files, changing directory to " + sourceDir + " or downloading a file went wrong. Aborting Download");
					e1.printStackTrace();
					return false;
				} 
				catch (FTPAbortedException e1) {
					logger.error("Listing for files, changing directory to " + sourceDir + " or downloading a file went wrong. Aborting Download");
					e1.printStackTrace();
					return false;
				} 
				catch (FTPListParseException e1) {
					logger.error("Listing for files, changing directory to " + sourceDir + " or downloading a file went wrong. Aborting Download");
					e1.printStackTrace();
					return false;
				} catch (ClassNotFoundException e) {
					logger.error("Could not instantiate FTPClient, thus no list of files could be made, aborting.");
					e.printStackTrace();
					return false;
				}
			}	
			else{
				logger.error("You can not send files if you are not logged in. Use login method first.");
				return false;
			}		
		}
	}
	
	
	/**
	 * Deletes the specified file in the destination directory
	 * 
	 * @param	file			The name of the file to delete, just the name no path required
	 * 
	 * @param	sourceDir		The path where the file is located in the FTP server
	 * 
	 * @return	TRUE if the deletion was successful
	 * 
	 */
	public boolean deleteFile(String file, String sourceDir){
		
		//check that given params are not empty
		if (file.isEmpty() || sourceDir.isEmpty()){
			logger.error("Some of the given parameters are void. Deleting aborted...");
			return false;
		}
		else{
			
			//check logged state
			if (this.logged){
						
				//change to destination directory in ftp
				try {
					
					String dir = client.currentDirectory();
					
					//change directory only if necessary
					if (!this.checkSameFolder(dir,sourceDir)){
						logger.info("Current directory is " + dir);
						logger.info("Changing directory to  " + sourceDir);
						client.changeDirectory(sourceDir);
						logger.info("Directory changed successfully, proceding to delete");
					}
											
					//we are placed in correct folder, procede to delete
					this.client.deleteFile(file);
					logger.info("File " + file  + " deleted successfully from " + sourceDir);
								
					return true;
						
					
				}				
				catch (IllegalStateException e) {
					logger.error("Could not change directory to: " + sourceDir + " or could not delete file " + file);
					e.printStackTrace();
					return false;
				} 
				catch (IOException e) {	
					logger.error("Could not change directory to: " + sourceDir + " or could not delete file " + file);
					e.printStackTrace();
					return false;
				} 
				catch (FTPIllegalReplyException e) {	
					logger.error("Could not change directory to: " + sourceDir + " or could not delete file " + file);
					e.printStackTrace();
					return false;
				} 
				catch (FTPException e) {
					logger.error("Could not change directory to: " + sourceDir + " or could not delete file " + file);
					e.printStackTrace();
					return false;
				}
			}
			else{
				logger.error("You can not delete a file if you are not logged in. Use login method first.");
				return false;
			}
		}
	}
	
	/**
	 * Deletes the set of files within the source directory 
	 * 
	 * @param	sourceDir	The source directory where the files are located
	 * 
	 * @return	<code>true</code> if the upload was successful
	 * 
	 */
	public boolean deleteDir(String sourceDir){
		
		//check that given params are not empty
		if (sourceDir.isEmpty()){
			logger.error("Some of the given parameters are void. Deletion aborted...");
			return false;
		}
		else{
			
			//check logged state
			if (this.logged){
				
				//change directory
				try {
				
					String dir = client.currentDirectory();
					
					//change directory only if necessary
					if (!this.checkSameFolder(dir, sourceDir)){
						logger.info("Current directory is " + dir);
						logger.info("Changing directory to  " + sourceDir);
						client.changeDirectory(sourceDir);
						logger.info("Directory changed successfully, proceding to delete");
					}
					
					
					//First delete all files within directory, most FTP servers wont delete a directory not empty
					//list files in source directory	
					Object o = Class.forName("it.sauronsoftware.ftp4j.FTPFile");
					logger.info("Instantiated FTPFile " + o.toString() + " list correctly. Gathering list of files");
					list = client.list();
					
					//check that there was something in the folder specified
					if (list.length!=0){
						//download each file
						for (int i=0; i<list.length; i++){	
							//check that we have a file
							if (list[i].getType()==FTPFile.TYPE_FILE){
								//get the filename
								String name = list[i].getName();
								//Delete file
								this.client.deleteFile(name);
								logger.info("File " + name  + " deleted successfully!");
							}
						}
						
						logger.info("All files deleted successfully from " + sourceDir );
						
						//Need to go up at least one level in the hierarchy to delete the folder, cannot be in CWD
						client.changeDirectoryUp();
						//check current directory
						String parent = client.currentDirectory();
						logger.info("Changed to parent directory: " + parent);
						
						//check if last char is /, then remove it
						if (sourceDir.endsWith("/")){
							sourceDir = sourceDir.substring(0, sourceDir.length() - 1);
						}
						
						//get name of children directory to delete, what is right hand of last / occurence 
						String childrenDir = sourceDir.substring(sourceDir.lastIndexOf("/") + 1);
						//check if we actually had a children dir
						if (childrenDir != null && !childrenDir.isEmpty()){
							//delete the directory
							this.client.deleteDirectory(childrenDir);
						}
						//if not it probably means that sourceDir was a first level directory different from / 
						else{
							//delete the directory
							this.client.deleteDirectory(sourceDir);
						}
						
						logger.info("Directory removed successfully: " + sourceDir);
						return true;
					}
					//if there were no files, abort download
					else{
						logger.error("There were no files in the given directory. Trying to delete the directory...");
						//delete the directory
						this.client.deleteDirectory(sourceDir);
						logger.info("Directory " + sourceDir + " deleted successfully!");
						return true;
					}
				} 
				catch (IllegalStateException e1) {
					logger.error("Listing for files, changing directory to " + sourceDir + " or deleting a file went wrong. Aborting Deletion");
					e1.printStackTrace();
					return false;
				} 
				catch (IOException e1) {
					logger.error("Listing for files, changing directory to " + sourceDir + " or deleting a file went wrong. Aborting Deletion");
					e1.printStackTrace();
					return false;
				} 
				catch (FTPIllegalReplyException e1) {
					logger.error("Listing for files, changing directory to " + sourceDir + " or deleting a file went wrong. Aborting Deletion");
					e1.printStackTrace();
					return false;
				} 
				catch (FTPException e1) {
					logger.error("Listing for files, changing directory to " + sourceDir + " or deleting a file went wrong. Aborting Dletion");
					e1.printStackTrace();
					return false;
				} 
				catch (FTPAbortedException e1) {
					logger.error("Listing for files, changing directory to " + sourceDir + " or deleting a file went wrong. Aborting Dletion");
					e1.printStackTrace();
					return false;
				} 
				catch (FTPListParseException e1) {
					logger.error("Listing for files, changing directory to " + sourceDir + " or deleting a file went wrong. Aborting Dletion");
					e1.printStackTrace();
					return false;
				}
				catch (FTPDataTransferException e) {
					logger.error("Listing for files, changing directory to " + sourceDir + " or deleting a file went wrong. Aborting Dletion");
					e.printStackTrace();
					return false;
				}
				catch (ClassNotFoundException e) {
					logger.error("Could not instantiate FTPClient, thus no list of files could be made, aborting.");
					e.printStackTrace();
					return false;
				} 
			}	
			else{
				logger.error("You can not delete files if you are not logged in. Use login method first.");
				return false;
			}		
		}
	}
	
	
	/**
	 * Helping method that gets the names of the files contained in a specified path
	 * 
	 * @param dirName	The path where file name searching is going to be done
	 * 
	 * @return	ArrayList<String>	A list with the files names
	 */
	private ArrayList<String> getFileNames(String dirName){
		
		//The return list
		ArrayList<String>  ret = new ArrayList<String>();
		
		//Check that given path exists
		if (!dirName.isEmpty()){
			
			File dir = new File(dirName);
				
			// This filter only returns files
			FileFilter fileFilter = new FileFilter() {
			    public boolean accept(File file) {
			        return file.isFile();
			    }
			};
			
			// The list of files can also be retrieved as File objects
			File[] files = dir.listFiles(fileFilter);
			
			//Check that there are some files 
			if (files == null) {
			    // Either dir does not exist or is not a directory
				logger.error("Specified directory is empty");
				return ret;
			} 
			else {
			    
				for (int i=0; i<files.length; i++) {
			        // Get filename of file or directory
			        String filename = files[i].getName();
			        System.out.println("File found in path " + dirName +", name is: " + filename);
			        ret.add(filename);
			    }
			}
		}
		//return list
		return ret;
		
	}
	
	
	/**
	 * Checks that the given directories names are not the same
	 * 
	 * @param 	sourceDir		The first directory name
	 * 
	 * @param	destDir			The second directory name
	 * 
	 * @return	<code>true</code> if both names are equal
	 */
	private boolean checkSameFolder(String sourceDir, String destDir){
		
		//Check that given parameters are not empty
		if (sourceDir.isEmpty() || destDir.isEmpty()){
			
			logger.error("None of the given names can be empty. Aborting comparisson");
			return false;
		}
		else{
			//To avoid modification of passed references
			String first = sourceDir;
			String second = destDir;
			//remove possible trailing slash from beginning and end before comparing, check is not root directory /
			if (first.startsWith("/") && first.length() > 1){
				first = first.substring(1);
			}
			else{
				if (first.endsWith("/") && first.length() > 1){
					first = first.substring(0, first.length()-1);
				}
			}
			if (second.startsWith("/") && second.length() > 1){
				second = second.substring(1);
			}
			else{
				if (second.endsWith("/") && second.length() > 1){
					second = second.substring(0, second.length()-1);
				}
			}
			//comparisson 
			if (first.equalsIgnoreCase(second)){
				logger.info("Given directories, " + sourceDir + " and " + destDir + " are most surely the same");
				return true;
			}
			else{
				logger.info("Given directories, " + sourceDir + " and " + destDir + " are most surely not the same");
				return false;
			}
		
		}
		
	}
	
	
	/**
	 *  Getters and setters
	 * 
	 */
	public String getHost() {
		return host;
	}

	public void setHost(String host) {
		this.host = host;
	}

	public int getPort() {
		return port;
	}

	public void setPort(int port) {
		this.port = port;
	}

	public String getUser() {
		return user;
	}

	public void setUser(String user) {
		this.user = user;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public boolean isBypass() {
		return bypass;
	}

	public void setBypass(boolean bypass) {
		this.bypass = bypass;
	}

	public boolean isSetup() {
		return setup;
	}

	public void setSetup(boolean setup) {
		this.setup = setup;
	}

	public boolean isConnected() {
		return connected;
	}

	public void setConnected(boolean connected) {
		this.connected = connected;
	}

	public boolean isLogged() {
		return logged;
	}

	public void setLogged(boolean logged) {
		this.logged = logged;
	}
	
	public secure getConnectionType() {
		return connectionType;
	}

	public void setConnectionType(secure connectionType) {
		this.connectionType = connectionType;
	}
}
