class ApplicationController < ActionController::Base
  # Prevent CSRF attacks by raising an exception.
  # For APIs, you may want to use :null_session instead.
  protect_from_forgery with: :exception

	require 'google/api_client'
	def oauth2       
	    @client = Google::APIClient.new    
	    @client.authorization.client_id = '521911819923-p5g3rj4hs2a2icj3itvqu023l7j6lnm7.apps.googleusercontent.com'
	    @client.authorization.client_secret = 'Bzx_xEzDOlcQ9K0l3IXYD8ih' 
	    @client.authorization.scope = 'https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email'        
	    @client.authorization.redirect_uri = http://localhost:3000/oauth2callback 
	    @client.authorization.code = params[:code] if params[:code]      
	    if session[:token_id]    
	      # Load the access token here if it's available       
	      token_pair = TokenPair.find(session[:token_id])      
	      @client.authorization.update_token!(token_pair.to_hash)        
	    end  
	    if @client.authorization.refresh_token && @client.authorization.expired?   
	      @client.authorization.fetch_access_token!  
	    end  
	    unless @client.authorization.access_token || request.path_info =~ /^\/oauth2/        
	      redirect_to oauth2authorize_url  
	    end  
	end   
end
