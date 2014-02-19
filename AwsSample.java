/*
 * Copyright 2010 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 * 
 * Modified by Sambit Sahu
 * Modified by Kyung-Hwa Kim (kk2515@columbia.edu)
 * 
 * 
 */
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import com.amazonaws.AmazonServiceException;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.PropertiesCredentials;
import com.amazonaws.regions.Region;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.ec2.AmazonEC2;
import com.amazonaws.services.ec2.AmazonEC2Client;
import com.amazonaws.services.ec2.model.AuthorizeSecurityGroupIngressRequest;
import com.amazonaws.services.ec2.model.CreateSecurityGroupRequest;
import com.amazonaws.services.ec2.model.CreateSecurityGroupResult;
import com.amazonaws.services.ec2.model.CreateKeyPairRequest;
import com.amazonaws.services.ec2.model.CreateKeyPairResult;
import com.amazonaws.services.ec2.model.CreateTagsRequest;
import com.amazonaws.services.ec2.model.DescribeAvailabilityZonesResult;
import com.amazonaws.services.ec2.model.DescribeImagesResult;
import com.amazonaws.services.ec2.model.DescribeInstancesResult;
import com.amazonaws.services.ec2.model.DescribeKeyPairsResult;
import com.amazonaws.services.ec2.model.DescribeSecurityGroupsResult;
import com.amazonaws.services.ec2.model.Image;
import com.amazonaws.services.ec2.model.Instance;
import com.amazonaws.services.ec2.model.InstanceState;
import com.amazonaws.services.ec2.model.IpPermission;
import com.amazonaws.services.ec2.model.KeyPair;
import com.amazonaws.services.ec2.model.Reservation;
import com.amazonaws.services.ec2.model.RunInstancesRequest;
import com.amazonaws.services.ec2.model.RunInstancesResult;
import com.amazonaws.services.ec2.model.StartInstancesRequest;
import com.amazonaws.services.ec2.model.StopInstancesRequest;
import com.amazonaws.services.ec2.model.Tag;
import com.amazonaws.services.ec2.model.TerminateInstancesRequest;
//import com.jcraft.jsch.*;
import ch.ethz.ssh2.Connection;
import ch.ethz.ssh2.Session;
import ch.ethz.ssh2.StreamGobbler;



public class AwsSample {
	//private static final long SLEEP_CYCLE = 10000;
    /*
     * Important: Be sure to fill in your AWS access credentials in the
     *            AwsCredentials.properties file before you try to run this
     *            sample.
     * http://aws.amazon.com/security-credentials
     */

    static AmazonEC2      ec2;

    public static void main(String[] args) throws Exception {


    	 AWSCredentials credentials = new PropertiesCredentials(
    			 AwsSample.class.getResourceAsStream("AwsCredentials.properties"));

         /*********************************************
          * 
          *  #1 Create Amazon Client object
          *  
          *********************************************/
    	 System.out.println("#1 Create Amazon Client object");
         ec2 = new AmazonEC2Client(credentials);
         //ec2.setEndpoint("ec2.us-west-2.amazonaws.com");
       
        try {
        	
        	/*********************************************
        	 * 
           *  #2 Describe Availability Zones.
           *  
           *********************************************/
        	System.out.println("#2 Describe Availability Zones.");
          DescribeAvailabilityZonesResult availabilityZonesResult = ec2.describeAvailabilityZones();
          System.out.println("You have access to " + availabilityZonesResult.getAvailabilityZones().size() +
                    " Availability Zones.");

          /*********************************************
           *                 
           *  #3 Describe Key Pair
           *                 
           *********************************************/
          System.out.println("#3 Describe Key Pair");
          DescribeKeyPairsResult dkr = ec2.describeKeyPairs();
          System.out.println(dkr.toString());
            
            
          /*********************************************
           * 
           *  #4 Describe Current Instances
           *  
           *********************************************/
          System.out.println("#4 Describe Current Instances");
          DescribeInstancesResult describeInstancesRequest = ec2.describeInstances();
          List<Reservation> reservations = describeInstancesRequest.getReservations();
          Set<Instance> instances = new HashSet<Instance>();
          // add all instances to a Set.
          for (Reservation reservation : reservations) {
          	instances.addAll(reservation.getInstances());
            }
            
          System.out.println("You have " + instances.size() + " Amazon EC2 instance(s).");
          for (Instance ins : instances){
          	
          	// instance id
          	String instanceId = ins.getInstanceId();
           	
          	// instance state
           	InstanceState is = ins.getState();
           	System.out.println(instanceId+" "+is.getName());
           }
            
          /*********************************************
           * 
           *  #5 Describe Security Group
           *                   
           *********************************************/
          System.out.println("#5 Describe Current Security Groups");
          DescribeSecurityGroupsResult dsgr = ec2.describeSecurityGroups();
          System.out.println(dsgr.toString());
          
          /*********************************************
           *             
           *   #6 Create New Security Group
           *  
           *********************************************/
          CreateSecurityGroupRequest securityGroupRequest = 
           		new CreateSecurityGroupRequest("Mini-HW2-securityGroup", "Security Group for Mini-HW2");
	       	CreateSecurityGroupResult result = ec2.createSecurityGroup(securityGroupRequest);
	        	
	      	System.out.println("#6 New Security Group Added : " + result.toString());
	       	String ipAddr = "0.0.0.0/0";

	       	// Get the IP of the current host, so that we can limit the Security Group
	  	   	// by default to the ip range associated with your subnet.
	  	   	try {
	  	   	    InetAddress addr = InetAddress.getLocalHost();

	  	   	    // Get IP Address
	      	    ipAddr = addr.getHostAddress()+"/10";
	 	    	} catch (UnknownHostException e) {
	 	    		}
	  	    	
	  	    // Create a range that you would like to populate.
	  	   	ArrayList<String> ipRanges = new ArrayList<String>();
	  	   	ipRanges.add(ipAddr);
	  	   	
	  	    // Open up port 23 for TCP traffic to the associated IP from above (e.g. ssh traffic).
	  	    ArrayList<IpPermission> ipPermissions = new ArrayList<IpPermission> ();
	  	    IpPermission sshIpPermission = new IpPermission();
	  	    sshIpPermission.setIpProtocol("tcp");
	  	    sshIpPermission.setFromPort(new Integer(22));
	  	    sshIpPermission.setToPort(new Integer(22));
	  	    sshIpPermission.setIpRanges(ipRanges);
	  	    ipPermissions.add(sshIpPermission);
	  	    	
	  	    //ArrayList<IpPermission> httpIpPermissions = new ArrayList<IpPermission> ();
	  	    IpPermission httpsIpPermission = new IpPermission();
	  	   	httpsIpPermission.withIpRanges("0.0.0.0/0").withIpProtocol("tcp").withFromPort(new Integer(443)).withToPort(new Integer(443));
	  	   	ipPermissions.add(httpsIpPermission);
	  	   	
	  	   	//ArrayList<IpPermission> sshIpPermissions = new ArrayList<IpPermission> ();
	      	IpPermission httpIpPermission = new IpPermission();
	 	    	httpIpPermission.withIpRanges("0.0.0.0/0").withIpProtocol("tcp").withFromPort(new Integer(80)).withToPort(new Integer(80));
	 	    	ipPermissions.add(httpIpPermission);
  	    	
	 	    	IpPermission tcpIpPermission = new IpPermission();
	 	    	tcpIpPermission.withIpRanges("0.0.0.0/0").withIpProtocol("tcp").withFromPort(new Integer(0)).withToPort(new Integer(65535));
	  	    ipPermissions.add(tcpIpPermission);
	  	    	
	  	   	AuthorizeSecurityGroupIngressRequest ingressRequest = 
	  	   			new AuthorizeSecurityGroupIngressRequest("Mini-HW2-securityGroup",ipPermissions);
			   	ec2.authorizeSecurityGroupIngress(ingressRequest);
            
			    /*********************************************
           * 
           *  #7 Create new key pair
           *  
           *********************************************/
		    	CreateKeyPairRequest ckpr = new CreateKeyPairRequest();
		    	ckpr.withKeyName("Mini-HW2-key");
			    System.out.println("#7 Create new key pair");	
			  	CreateKeyPairResult ckpresult = ec2.createKeyPair(ckpr);
			   	KeyPair keypair = ckpresult.getKeyPair();
			   	String privateKey = keypair.getKeyMaterial();
			   	
			   	System.out.println("Writing new key pair to file");	
		    	String fileName="Mini-HW2-key.pem"; 
		    	File distFile = new File(fileName); 
          BufferedReader bufferedReader = new BufferedReader(new StringReader(privateKey));
          BufferedWriter bufferedWriter = new BufferedWriter(new FileWriter(distFile)); 
          char buf[] = new char[1024];        
          int len; 
          while ((len = bufferedReader.read(buf)) != -1) { 
          	bufferedWriter.write(buf, 0, len); 
          } 
          bufferedWriter.flush(); 
          bufferedReader.close(); 
          bufferedWriter.close();
          
          //Changing permissions to 400
          Path path = Paths.get("Mini-HW2-key.pem");
          Set<PosixFilePermission> perms = PosixFilePermissions.fromString("r--------");  
          //FileAttribute<Set<PosixFilePermission>> att = PosixFilePermissions.asFileAttribute(set);
          Files.setPosixFilePermissions(path, perms);
			    	
			    	
          /*********************************************
           * 
           *  #8 Create an Instance
           *              
           *********************************************/
           
          System.out.println("#8 Create an Instance");
          String imageId = "ami-bba18dd2"; //Basic 64-bit Amazon Linux AMI
          int minInstanceCount = 1; // create 1 instance
          int maxInstanceCount = 1;
          RunInstancesRequest rir = new RunInstancesRequest(imageId, minInstanceCount, maxInstanceCount);
          rir.setInstanceType("t1.micro");
          rir.withKeyName("Mini-HW2-key");
          rir.withSecurityGroups("Mini-HW2-securityGroup");
            
          RunInstancesResult runInstanceResult = ec2.runInstances(rir);
            
          System.out.println("waiting");
          Thread.currentThread().sleep(100000);
          System.out.println("OK");
            
            //get instanceId from the result
          List<Instance> resultInstance = runInstanceResult.getReservation().getInstances();
          String createdInstanceId = null;
          for (Instance ins : resultInstance){
          	createdInstanceId = ins.getInstanceId();
           	System.out.println("New instance has been created: "+ins.getInstanceId());
          }
            
          describeInstancesRequest = ec2.describeInstances();
          reservations = describeInstancesRequest.getReservations();
          int k = reservations.size();
          Reservation tempReservation = reservations.get(k-1);
          Instance tempInstances = tempReservation.getInstances().get(0);
          System.out.println("The public DNS is: "+tempInstances.getPublicDnsName()+"\n"+tempInstances.getRamdiskId());
          System.out.println("The private IP is: "+tempInstances.getPrivateIpAddress());
          System.out.println("The public IP is: "+tempInstances.getPublicIpAddress());
            
          /*********************************************
           * 
           *  #9 Create a 'tag' for the new instance.
           *  
           *********************************************/
            
          System.out.println("#9 Create a 'tag' for the new instance.");
          List<String> resources = new LinkedList<String>();
          List<Tag> tags = new LinkedList<Tag>();
          Tag nameTag = new Tag("Name", "Mini-HW2-Instance");
           
          resources.add(createdInstanceId);
          tags.add(nameTag);
           
          CreateTagsRequest ctr = new CreateTagsRequest(resources, tags);
          ec2.createTags(ctr);
            
          System.out.println("waiting");
          Thread.currentThread().sleep(40000);
          System.out.println("OK");
            
          /*********************************************
           * 
           *   #10 SSH
           *  
           *********************************************/
          String hostname = tempInstances.getPublicDnsName();
          String username = "ec2-user";
          File keyFile = new File("Mini-HW2-key.pem");
          String keyFilePass = "";
          
          System.out.println("SSHing...");
          
          try
        	{
     			/* Create a connection instance */
     			Connection conn = new Connection(hostname);
     			/* Now connect */
       		conn.connect();
     			/* Authenticate */
     			boolean isAuthenticated = conn.authenticateWithPublicKey(username, keyFile, keyFilePass);
        	if (isAuthenticated == false)
       			throw new IOException("Authentication failed.");
      			/* Create a session */
       			Session sess = conn.openSession();
       			System.out.println("Now inside remote AWS instance:");
       			sess.execCommand("whoami");
       			InputStream stdout = new StreamGobbler(sess.getStdout());
       			BufferedReader br = new BufferedReader(new InputStreamReader(stdout));
       			System.out.println("Running command whoami");
       			while (true)
       			{
        			String line = br.readLine();
        			if (line == null)
       					break;
       				System.out.println(line);
       			}
      			/* Close this session */
       			sess.close();
       			/* Close the connection */
       			conn.close();
       			}
        		catch (IOException e)
        		{
        			e.printStackTrace(System.err);
        			System.exit(2);
        		}
               
          /*********************************************
           * 
           *  #11 Stop/Start an Instance
           *  
           *********************************************/
          /*
            System.out.println("#7 Stop the Instance");
            List<String> instanceIds = new LinkedList<String>();
            instanceIds.add(createdInstanceId);
            
            //stop
            StopInstancesRequest stopIR = new StopInstancesRequest(instanceIds);
            //ec2.stopInstances(stopIR);
            
            //start
            StartInstancesRequest startIR = new StartInstancesRequest(instanceIds);
            //ec2.startInstances(startIR);
            
            */
            /*********************************************
             * 
             *  #12 Terminate an Instance
             *  
             *********************************************/
            /*
            System.out.println("#8 Terminate the Instance");
            TerminateInstancesRequest tir = new TerminateInstancesRequest(instanceIds);
            //ec2.terminateInstances(tir);
            
                        */
            /*********************************************
             *  
             *  #13 shutdown client object
             *  
             *********************************************/
            //ec2.shutdown();
            
            
            
        } catch (AmazonServiceException ase) {
                System.out.println("Caught Exception: " + ase.getMessage());
                System.out.println("Reponse Status Code: " + ase.getStatusCode());
                System.out.println("Error Code: " + ase.getErrorCode());
                System.out.println("Request ID: " + ase.getRequestId());
        }

        
    }
}
