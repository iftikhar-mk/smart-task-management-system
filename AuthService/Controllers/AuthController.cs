using AuthService.DTOs;
using AuthService.Interfaces;
using AuthService.Models;
using AuthService.Services;
using AutoMapper;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Shared.DTOs;
using Shared.Enums;

namespace AuthService.Controllers
{
    [ApiController]
    [Route("api/auth")]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly SignInManager<AppUser> _signInManager;
        private readonly IJwtTokenGenerator _jwtTokenService;
        private readonly IMapper _mapper;
        private readonly ITokenProvider _tokenProvider;

        public AuthController(UserManager<AppUser> userManager, SignInManager<AppUser> signInManager, IJwtTokenGenerator jwtTokenService, IMapper mapper, ITokenProvider tokenProvider)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _jwtTokenService = jwtTokenService;
            _mapper = mapper;
            _tokenProvider = tokenProvider;
        }

        /// <summary>
        /// Registers a new user account with default role 'User'.
        /// </summary>
        /// <param name="dto">Registration details including username, email, and password.</param>
        /// <returns>Returns a ResponseDto with success status or validation errors.</returns>
        [HttpPost("register")]
        [AllowAnonymous]
        public async Task<IActionResult> Register(RegisterDto dto)
        {
            try
            {
                var user = new AppUser
                {
                    UserName = dto.UserName,
                    Email = dto.Email,
                    DisplayName = dto.DisplayName
                };

                var result = await _userManager.CreateAsync(user, dto.Password);
                if (!result.Succeeded)
                    return BadRequest(new ResponseDto { Message = "User creation failed.", Result = result.Errors });

                await _userManager.AddToRoleAsync(user, AppRole.User.ToString());

                var userDto = _mapper.Map<AppUserDto>(user);
                userDto.Roles = (await _userManager.GetRolesAsync(user)).ToList();

                return Ok(new ResponseDto
                {
                    Result = userDto,
                    Message = "Registration successful.",
                    isSuccess = true
                });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new ResponseDto { Message = $"Server error: {ex.InnerException?.Message ?? ex.Message}" });
            }
        }

        /// <summary>
        /// Authenticates a user and returns their JWT token and profile.
        /// </summary>
        /// <param name="dto">Login credentials: email and password.</param>
        /// <returns>Returns a ResponseDto with token and user info or error.</returns>
        [HttpPost("login")]
        [AllowAnonymous]
        public async Task<IActionResult> Login(LoginDto dto)
        {
            try
            {
                var user = await _userManager.FindByEmailAsync(dto.Email);
                if (user == null)
                    return Unauthorized(new ResponseDto { Message = "Invalid credentials" });

                if (user.IsDisabled)
                    return Unauthorized(new ResponseDto { Message = "User is disabled. Please contact your admin." });

                var result = await _signInManager.CheckPasswordSignInAsync(user, dto.Password, false);
                if (!result.Succeeded)
                    return Unauthorized(new ResponseDto { Message = "Invalid credentials" });

                var (token, userDto) = await _jwtTokenService.GenerateTokenAsync(user);

                _tokenProvider.SetToken(token);

                return Ok(new ResponseDto
                {
                    Result = new AuthResponseDto { User = userDto, Token = token },
                    Message = "Login successful.",
                    isSuccess = true
                });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new ResponseDto { Message = $"Server error: {ex.InnerException?.Message ?? ex.Message}" });
            }
        }

        /// <summary>
        /// Retrieves the authenticated user's profile and assigned roles.
        /// </summary>
        /// <returns>Returns current user's AppUserDto via ResponseDto.</returns>
        [Authorize]
        [HttpGet("profile")]
        public async Task<IActionResult> GetCurrentUserProfile()
        {
            try
            {
                var user = await _userManager.GetUserAsync(User);
                if (user == null)
                    return NotFound(new ResponseDto { Message = "User not found" });

                var roles = await _userManager.GetRolesAsync(user);
                var dto = _mapper.Map<AppUserDto>(user);
                dto.Roles = roles.ToList();

                return Ok(new ResponseDto
                {
                    Result = dto,
                    isSuccess = true,
                    Message = "Ok"
                });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new ResponseDto { Message = $"Server error: {ex.InnerException?.Message ?? ex.Message}" });
            }
        }

        /// <summary>
        /// Updates profile for the current user or another user depending on role.
        /// </summary>
        /// <param name="dto">Profile updates (DisplayName, optional roles).</param>
        /// <returns>Returns updated AppUserDto via ResponseDto.</returns>
        [Authorize]
        [HttpPut("update-profile")]
        public async Task<IActionResult> UpdateProfile(AppUserDto dto)
        {
            try
            {
                if (string.IsNullOrEmpty(dto.Id))
                    return BadRequest(new ResponseDto { Message = "'id' is required" });

                var currentUser = await _userManager.GetUserAsync(User);
                var currentUserId = currentUser?.Id;
                var currentRoles = await _userManager.GetRolesAsync(currentUser);
                var isUserOnly = currentRoles.Contains(AppRole.User.ToString());

                AppUser targetUser = currentUserId == dto.Id ? currentUser : await _userManager.FindByIdAsync(dto.Id);
                if (targetUser == null)
                    return NotFound(new ResponseDto { Message = "User not found" });

                targetUser.DisplayName = dto.DisplayName;
                var result = await _userManager.UpdateAsync(targetUser);
                if (!result.Succeeded)
                    return BadRequest(new ResponseDto { Message = "Profile update failed", Result = result.Errors });

                if (!isUserOnly && dto.Roles?.Any() == true)
                {
                    var existingRoles = await _userManager.GetRolesAsync(targetUser);
                    await _userManager.RemoveFromRolesAsync(targetUser, existingRoles);
                    await _userManager.AddToRolesAsync(targetUser, dto.Roles);
                }

                var updatedRoles = await _userManager.GetRolesAsync(targetUser);
                var updatedDto = _mapper.Map<AppUserDto>(targetUser);
                updatedDto.Roles = updatedRoles.ToList();

                return Ok(new ResponseDto
                {
                    Result = updatedDto,
                    isSuccess = true,
                    Message = "Profile updated"
                });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new ResponseDto { Message = $"Server error: {ex.InnerException?.Message ?? ex.Message}" });
            }
        }

        /// <summary>
        /// Updates the current user's password.
        /// </summary>
        /// <param name="dto">Old password and new password.</param>
        /// <returns>Returns success or failure message via ResponseDto.</returns>
        [Authorize]
        [HttpPost("update-password")]
        public async Task<IActionResult> UpdatePassword(UpdatePasswordDto dto)
        {
            try
            {
                var user = await _userManager.GetUserAsync(User);
                if (user == null)
                    return NotFound(new ResponseDto { Message = "User not found" });

                var result = await _userManager.ChangePasswordAsync(user, dto.CurrentPassword, dto.NewPassword);
                if (!result.Succeeded)
                    return BadRequest(new ResponseDto { Message = "Password update failed", Result = result.Errors });

                return Ok(new ResponseDto
                {
                    Result = result,
                    isSuccess = true,
                    Message = "Password updated successfully"
                });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new ResponseDto { Message = $"Server error: {ex.InnerException?.Message ?? ex.Message}" });
            }
        }
    }
}



//using AuthService.DTOs;
//using AuthService.Interfaces;
//using AuthService.Models;
//using AuthService.Services;
//using AutoMapper;
//using Microsoft.AspNetCore.Authorization;
//using Microsoft.AspNetCore.Identity;
//using Microsoft.AspNetCore.Mvc;
//using Shared.DTOs;
//using Shared.Enums;

//namespace AuthService.Controllers
//{
//    [ApiController]
//    [Route("api/auth")]
//    public class AuthController : ControllerBase
//    {
//        private readonly UserManager<AppUser> _userManager;
//        private readonly SignInManager<AppUser> _signInManager;
//        private readonly JwtTokenGenerator _jwtTokenService;
//        private readonly IMapper _mapper;
//        private readonly ResponseDto _responseDto;
//        private readonly ITokenProvider _tokenProvider;

//        public AuthController(UserManager<AppUser> userManager, SignInManager<AppUser> signInManager,
//            JwtTokenGenerator jwtTokenService, IMapper mapper, ITokenProvider tokenProvider)
//        {
//            _userManager = userManager;
//            _signInManager = signInManager;
//            _jwtTokenService = jwtTokenService;
//            _mapper = mapper;
//            _responseDto = new ResponseDto();
//            _tokenProvider = tokenProvider;
//        }

//        /// <summary>
//        /// Registers a new user account using the provided registration data.
//        /// </summary>
//        /// <returns>Returns a ResponseDto with success status or validation errors.</returns>
//        [HttpPost("register")]
//        [AllowAnonymous]
//        public async Task<IActionResult> Register(RegisterDto dto)
//        {
//            try
//            {
//                //if (!Enum.TryParse<AppRole>(dto.Role, true, out var roleEnum))
//                //    return BadRequest(new ResponseDto { Message = "Invalid role specified." });

//                //if (roleEnum != AppRole.User)
//                //    throw new BadHttpRequestException("Can't create user with role admin");

//                var user = new AppUser
//                {
//                    UserName = dto.UserName,
//                    Email = dto.Email,
//                    DisplayName = dto.DisplayName,
//                };

//                var result = await _userManager.CreateAsync(user, dto.Password);
//                if (!result.Succeeded)
//                    return BadRequest(new ResponseDto { Message = "User creation failed.", Result = result.Errors });

//                // await _userManager.AddToRoleAsync(user, roleEnum.ToString());

//                await _userManager.AddToRoleAsync(user, AppRole.User.ToString());

//                var userDto = _mapper.Map<AppUserDto>(user);
//                if (userDto.Roles.Count() <= 0)
//                {
//                    var roles = (List<string>)await _userManager.GetRolesAsync(user);
//                    userDto.Roles = roles;
//                }

//                _responseDto.Result = userDto;
//                _responseDto.Message = "Registration successful.";
//                _responseDto.isSuccess = true;
//                return Ok(_responseDto);
//            }
//            catch (Exception ex)
//            {
//                _responseDto.Message = $"Server error: {ex.InnerException?.Message ?? ex.Message}";
//                return StatusCode(500, _responseDto);
//            }
//        }

//        /// <summary>
//        /// Allows user login using the provided data.
//        /// </summary>
//        /// <returns>Returns a ResponseDto with success status or validation errors.</returns>
//        [HttpPost("login")]
//        [AllowAnonymous]
//        public async Task<IActionResult> Login(LoginDto dto)
//        {
//            try
//            {
//                var user = await _userManager.FindByEmailAsync(dto.Email);
//                if (user == null)
//                    return Unauthorized(new ResponseDto { Message = "Invalid credentials" });

//                var result = await _signInManager.CheckPasswordSignInAsync(user, dto.Password, false);
//                if (!result.Succeeded)
//                    return Unauthorized(new ResponseDto { Message = "Invalid credentials" });

//                var (token, userDto) = await _jwtTokenService.GenerateTokenAsync(user);

//                var response = new AuthResponseDto
//                {
//                    User = userDto,
//                    Token = token
//                };

//                if (token is not null)
//                {
//                    _tokenProvider.SetToken(token);
//                }

//                _responseDto.Result = response;
//                _responseDto.Message = "Login successful.";
//                _responseDto.isSuccess = true;
//                return Ok(_responseDto);
//            }
//            catch (Exception ex)
//            {
//                _responseDto.Message = $"Server error: {ex.InnerException?.Message ?? ex.Message}";
//                return StatusCode(500, _responseDto);
//            }
//        }

//        /// <summary>
//        /// Authenticates a user and returns their JWT token along with user profile.
//        /// </summary>
//        /// <returns>Returns token and user information in ResponseDto.</returns>
//        [Authorize]
//        [HttpGet("profile")]
//        public async Task<IActionResult> GetCurrentUserProfile()
//        {
//            try
//            {
//                var user = await _userManager.GetUserAsync(User);
//                if (user == null)
//                    return NotFound(new ResponseDto { Message = "User not found" });

//                var roles = await _userManager.GetRolesAsync(user);
//                var dto = new AppUserDto
//                {
//                    Id = user.Id,
//                    UserName = user.UserName,
//                    Email = user.Email,
//                    DisplayName = user.DisplayName,
//                    Roles = roles.ToList()
//                };

//                _responseDto.Result = dto;
//                _responseDto.isSuccess = true;
//                _responseDto.Message = "Ok";

//                return Ok(_responseDto);
//            }
//            catch (Exception ex)
//            {
//                _responseDto.Message = $"Server error: {ex.InnerException?.Message ?? ex.Message}";
//                return StatusCode(500, _responseDto);
//            }
//        }

//        /// <summary>
//        /// Fetches profile of a specific user. Requires Admin or Moderator role.
//        /// </summary>
//        /// <returns>Returns User profile of the provided user.</returns>
//        [Authorize(Roles = "Admin,Moderator")]
//        [HttpGet("users/{userId}")]
//        public async Task<IActionResult> GetUserById(string userId)
//        {
//            try
//            {
//                var user = await _userManager.FindByIdAsync(userId);
//                if (user == null)
//                    return NotFound(new ResponseDto { Message = "User not found" });

//                var roles = await _userManager.GetRolesAsync(user);
//                var dto = new AppUserDto
//                {
//                    Id = user.Id,
//                    UserName = user.UserName,
//                    Email = user.Email,
//                    DisplayName = user.DisplayName,
//                    Roles = roles.ToList()
//                };

//                _responseDto.Result = dto;
//                _responseDto.Message = "Ok";
//                _responseDto.isSuccess = true;

//                return Ok(_responseDto);
//            }
//            catch (Exception ex)
//            {
//                _responseDto.Message = $"Server error: {ex.InnerException?.Message ?? ex.Message}";
//                return StatusCode(500, _responseDto);
//            }
//        }

//        /// <summary>
//        /// Returns a list of all users in the system. Requires Admin or Moderator role.
//        /// </summary>
//        /// <returns>Returns list of AppUserDto via ResponseDto.</returns>
//        [Authorize(Roles = "Admin,Moderator")]
//        [HttpGet("users")]
//        public async Task<IActionResult> GetAllUsers()
//        {
//            try
//            {
//                var users = _userManager.Users.ToList();
//                var userDtos = new List<AppUserDto>();

//                foreach (var user in users)
//                {
//                    var roles = await _userManager.GetRolesAsync(user);
//                    userDtos.Add(new AppUserDto
//                    {
//                        Id = user.Id,
//                        UserName = user.UserName,
//                        Email = user.Email,
//                        DisplayName = user.DisplayName,
//                        Roles = roles.ToList()
//                    });
//                }

//                _responseDto.Result = userDtos;
//                _responseDto.isSuccess = true;
//                _responseDto.Message = "Ok";

//                return Ok(_responseDto);
//            }
//            catch (Exception ex)
//            {
//                _responseDto.Message = $"Server error: {ex.InnerException?.Message ?? ex.Message}";
//                return StatusCode(500, _responseDto);
//            }
//        }

//        /// <summary>
//        /// Updates the current user's display name using the provided profile data.
//        /// </summary>
//        /// <returns>Returns updated AppUserDto via ResponseDto.</returns>
//        [Authorize]
//        [HttpPut("update-profile")]
//        public async Task<IActionResult> UpdateProfile(AppUserDto dto)
//        {
//            try
//            {
//                if(string.IsNullOrEmpty(dto.Email) || string.IsNullOrEmpty(dto.Id))
//                {
//                    _responseDto.Message = "'email' or 'id' is required";
//                    return BadRequest(_responseDto);
//                }

//                var loggedInUser = await _userManager.GetUserAsync(User);
//                var loggedInUserRoles = await _userManager.GetRolesAsync(loggedInUser);

//                var isNonAdminUser = loggedInUserRoles.ToList().Any(role => role == AppRole.User.ToString());

//                AppUser user = loggedInUser;                
//                if (loggedInUser != _mapper.Map<AppUser>(dto))
//                {
//                    if(!string.IsNullOrEmpty(dto.Email))
//                    {
//                        user = _userManager.Users.FirstOrDefault(u => u.Email == dto.Email);
//                    }
//                    else if (!string.IsNullOrEmpty(dto.Id))
//                    {
//                        user = _userManager.Users.FirstOrDefault(u => u.Id == dto.Id);
//                    }

//                    if (user == null)
//                    {
//                        _responseDto.Message = "User not found";
//                        return NotFound(_responseDto);
//                    }
//                }

//                user.DisplayName = dto.DisplayName;

//                var result = await _userManager.UpdateAsync(user);

//                if (!result.Succeeded)
//                    return BadRequest(new ResponseDto { Message = "Profile update failed", Result = result.Errors });

//                var roles = await _userManager.GetRolesAsync(user);

//                if (!isNonAdminUser)
//                {
//                    if (result != null && roles != null && roles.Count() > 0)
//                    {
//                        if (dto.Roles != null && dto.Roles.Count() > 0)
//                        {
//                            var removeResult = await _userManager.RemoveFromRolesAsync(user, roles.ToList());
//                            if (!removeResult.Succeeded)
//                            {
//                                Console.Write("Failed to remove roles: " + string.Join(", ", removeResult.Errors));
//                            }

//                            var addResult = await _userManager.AddToRolesAsync(user, dto.Roles.ToList());
//                            if (!addResult.Succeeded)
//                            {
//                                Console.WriteLine("Failed to add roles: " + string.Join(", ", addResult.Errors));
//                            }

//                            roles = await _userManager.GetRolesAsync(user);
//                        }
//                    }
//                }

//                var updatedDto = new AppUserDto
//                {
//                    Id = user.Id,
//                    UserName = user.UserName,
//                    Email = user.Email,
//                    DisplayName = user.DisplayName,
//                    Roles = roles.ToList()
//                };

//                _responseDto.Result = updatedDto;
//                _responseDto.isSuccess = true;
//                _responseDto.Message = "Ok";

//                return Ok(_responseDto);
//            }
//            catch (Exception ex)
//            {
//                _responseDto.Message = $"Server error: {ex.InnerException?.Message ?? ex.Message}";
//                return StatusCode(500, _responseDto);
//            }
//        }

//        /// <summary>
//        /// Updates the authenticated user's password securely.
//        /// </summary>
//        [Authorize]
//        [HttpPost("update-password")]
//        public async Task<IActionResult> UpdatePassword(UpdatePasswordDto dto)
//        {
//            try
//            {
//                var user = await _userManager.GetUserAsync(User);
//                if (user == null)
//                    return NotFound(new ResponseDto { Message = "User not found" });

//                var result = await _userManager.ChangePasswordAsync(user, dto.CurrentPassword, dto.NewPassword);
//                if (!result.Succeeded)
//                    return BadRequest(new ResponseDto { Message = "Password update failed", Result = result.Errors });

//                _responseDto.Result = result;
//                _responseDto.isSuccess = true;
//                _responseDto.Message = "Password updated successfully";

//                return Ok(_responseDto);
//            }
//            catch (Exception ex)
//            {
//                _responseDto.Message = $"Server error: {ex.InnerException?.Message ?? ex.Message}";
//                return StatusCode(500, _responseDto);
//            }
//        }

//        /// <summary>
//        /// Assigns a new role to the specified user. Requires Admin role.
//        /// </summary>
//        /// <returns>Returns Ok if successful.</returns>
//        [Authorize(Roles = "Admin,Moderator")]
//        [HttpPost("assign-role")]
//        public async Task<IActionResult> AssignRoleToUser(ManageUserRoleDto dto)
//        {
//            try
//            {
//                if (!Enum.TryParse<AppRole>(dto.Role, true, out var roleEnum))
//                    return BadRequest(new ResponseDto { Message = "Invalid role specified" });

//                var user = await _userManager.FindByIdAsync(dto.UserId);
//                if (user == null)
//                    return NotFound(new ResponseDto { Message = "User not found" });

//                var existingRoles = await _userManager.GetRolesAsync(user);
//                if (existingRoles.Contains(roleEnum.ToString()))
//                    return BadRequest(new ResponseDto { Message = "User already has this role" });

//                var result = await _userManager.AddToRoleAsync(user, roleEnum.ToString());
//                if (!result.Succeeded)
//                    return BadRequest(new ResponseDto { Message = "Role assignment failed", Result = result.Errors });

//                _responseDto.Result = result;
//                _responseDto.isSuccess = true;
//                _responseDto.Message = "Role assigned successfully";

//                return Ok(_responseDto);
//            }
//            catch (Exception ex)
//            {
//                _responseDto.Message = $"Server error: {ex.InnerException?.Message ?? ex.Message}";
//                return StatusCode(500, _responseDto);
//            }
//        }

//        //        /// <summary>
//        //        /// Removes a role from the specified user. Prevents self-removal of Admin role.
//        //        /// </summary>
//        //        /// <returns>Returns NoContent if successful or error if blocked.</returns>
//        [Authorize(Roles = "Admin,Moderator")]
//        [HttpPost("revoke-role")]
//        public async Task<IActionResult> RevokeRoleFromUser(ManageUserRoleDto dto)
//        {
//            try
//            {
//                if (!Enum.TryParse<AppRole>(dto.Role, true, out var roleEnum))
//                {
//                    _responseDto.Message = "Invalid role specified";
//                    return BadRequest(_responseDto);
//                }

//                var user = await _userManager.FindByIdAsync(dto.UserId);
//                if (user == null)
//                {
//                    _responseDto.Message = "User not found";
//                    return NotFound(_responseDto);
//                }

//                // Prevent self-demotion of Admin role
//                var currentUserId = _userManager.GetUserId(User);
//                if (user.Id == currentUserId && roleEnum == AppRole.Admin)
//                {
//                    _responseDto.Message = "You cannot remove your own Admin role.";
//                    return BadRequest(_responseDto);
//                }

//                var existingRoles = await _userManager.GetRolesAsync(user);
//                if (existingRoles.Contains(roleEnum.ToString()))
//                {
//                    _responseDto.Message = "User already has this role";
//                    return BadRequest(_responseDto);
//                }
//                var result = await _userManager.RemoveFromRoleAsync(user, roleEnum.ToString());
//                if (!result.Succeeded)
//                {
//                    _responseDto.Message = "Role removal failed";
//                    _responseDto.Result = result.Errors;
//                    return BadRequest(_responseDto);
//                }

//                _responseDto.Result = result;
//                _responseDto.isSuccess = true;
//                _responseDto.Message = "Role assigned successfully";

//                return Ok(_responseDto);
//            }
//            catch (Exception ex)
//            {
//                _responseDto.Message = $"Server error: {ex.InnerException?.Message ?? ex.Message}";
//                return StatusCode(500, _responseDto);
//            }
//        }
//    }
//}
