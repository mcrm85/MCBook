class User < ActiveRecord::Base
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable and :omniauthable
  devise :database_authenticatable, :registerable, 
         :recoverable, :rememberable, :trackable, :validatable

  attr_accessible :name, :last_name, :email,  :password, :encrypted_password

  has_many :statuses
 
  def fullName
  	name+ " "+ last_name
  end
end
