using AuthService.DTOs;
using AuthService.Models;
using AutoMapper;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Shared.DTOs;
using Shared.Enums;

namespace AuthService.Controllers
{
    [ApiController]
    [Route("api/user-admin")]
    [Authorize(Roles = "Admin,Manager,Moderator")]
    public class UserAdminController : ControllerBase
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly IMapper _mapper;

        public UserAdminController(UserManager<AppUser> userManager, IMapper mapper)
        {
            _userManager = userManager;
            _mapper = mapper;
        }

        /// <summary>
        /// Creates a new user with default role 'User'. Admin or Manager access only.
        /// </summary>
        [HttpPost("create-user")]
        public async Task<IActionResult> CreateUser(RegisterDto dto)
        {
            var response = new ResponseDto();

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

                response.Result = userDto;
                response.Message = "User created";
                response.isSuccess = true;
                return Ok(response);
            }
            catch (Exception ex)
            {
                response.Message = $"Server error: {ex.InnerException?.Message ?? ex.Message}";
                return StatusCode(500, response);
            }
        }

        /// <summary>
        /// Soft-disables a user by setting IsDisabled = true.
        /// </summary>
        [HttpPatch("set-user-status")]
        public async Task<IActionResult> SetUserStatus(SetUserStatusDto dto)
        {
            var response = new ResponseDto();

            try
            {
                var user = await _userManager.FindByIdAsync(dto.UserId);
                if (user == null)
                    return NotFound(new ResponseDto { Message = "User not found." });

                user.IsDisabled = dto.IsDisabled;

                var result = await _userManager.UpdateAsync(user);
                if (!result.Succeeded)
                    return BadRequest(new ResponseDto { Message = "Status update failed.", Result = result.Errors });

                response.Message = "User status updated successfully";
                response.isSuccess = true;
                return Ok(response);
            }
            catch (Exception ex)
            {
                response.Message = $"Server error: {ex.InnerException?.Message ?? ex.Message}";
                return StatusCode(500, response);
            }
        }

        /// <summary>
        /// Permanently deletes a user. Admin only recommended.
        /// </summary>
        [HttpDelete("delete-user/{id}")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> DeleteUser(string id)
        {
            var response = new ResponseDto();

            try
            {
                var user = await _userManager.FindByIdAsync(id);
                if (user == null)
                    return NotFound(new ResponseDto { Message = "User not found." });

                var result = await _userManager.DeleteAsync(user);
                if (!result.Succeeded)
                    return BadRequest(new ResponseDto { Message = "Deletion failed.", Result = result.Errors });

                response.Message = "User deleted permanently";
                response.isSuccess = true;
                return Ok(response);
            }
            catch (Exception ex)
            {
                response.Message = $"Server error: {ex.InnerException?.Message ?? ex.Message}";
                return StatusCode(500, response);
            }
        }

        /// <summary>
        /// Assigns a new role to a user.
        /// </summary>
        [HttpPost("assign-role")]
        public async Task<IActionResult> AssignRole(ManageUserRoleDto dto)
        {
            var response = new ResponseDto();

            try
            {
                var rolesList = GetRoles(dto);

                var user = await _userManager.FindByIdAsync(dto.UserId);
                if (user == null)
                    return NotFound(new ResponseDto { Message = "User not found." });

                var result = await _userManager.AddToRolesAsync(user, rolesList);
                if (!result.Succeeded)
                    return BadRequest(new ResponseDto { Message = "Role assignment failed.", Result = result.Errors });

                response.Message = "Role assigned successfully";
                response.isSuccess = true;
                return Ok(response);
            }
            catch (Exception ex)
            {
                response.Message = $"Server error: {ex.InnerException?.Message ?? ex.Message}";
                return StatusCode(500, response);
            }
        }

        /// <summary>
        /// Revokes a role from a user. Prevents self-demotion from Admin.
        /// </summary>
        [HttpPost("revoke-role")]
        public async Task<IActionResult> RevokeRole(ManageUserRoleDto dto)
        {
            var response = new ResponseDto();

            try
            {
                var rolesList = GetRoles(dto);

                var user = await _userManager.FindByIdAsync(dto.UserId);
                if (user == null)
                    return NotFound(new ResponseDto { Message = "User not found." });

                var currentUserId = _userManager.GetUserId(User);
                if (user.Id == currentUserId && rolesList.IndexOf(AppRole.Admin.ToString()) >= 0)
                    return BadRequest(new ResponseDto { Message = "You cannot remove your own Admin role." });

                var roles = await _userManager.GetRolesAsync(user);

                foreach (var r in rolesList)
                {
                    if (!roles.Contains(r))
                        return BadRequest(new ResponseDto { Message = $"User does not have the specified role: {r}" });
                }

                var result = await _userManager.RemoveFromRolesAsync(user, rolesList);
                if (!result.Succeeded)
                    return BadRequest(new ResponseDto { Message = "Role removal failed.", Result = result.Errors });


                user = await _userManager.FindByIdAsync(dto.UserId);
                roles = await _userManager.GetRolesAsync(user);

                AppUserDto userDto = new AppUserDto();
                userDto = _mapper.Map<AppUserDto>(user);
                userDto.Roles = roles.ToList();

                response.Result = userDto;
                response.Message = "Role revoked successfully";
                response.isSuccess = true;
                return Ok(response);
            }
            catch (Exception ex)
            {
                response.Message = $"Server error: {ex.InnerException?.Message ?? ex.Message}";
                return StatusCode(500, response);
            }
        }

        /// <summary>
        /// Lists all users with role info.
        /// </summary>
        [HttpGet("users")]
        public async Task<IActionResult> GetAllUsers()
        {
            var response = new ResponseDto();

            try
            {
                var users = _userManager.Users.ToList();
                var userDtos = new List<AppUserDto>();

                foreach (var user in users)
                {
                    var roles = await _userManager.GetRolesAsync(user);
                    userDtos.Add(new AppUserDto
                    {
                        Id = user.Id,
                        UserName = user.UserName,
                        Email = user.Email,
                        DisplayName = user.DisplayName,
                        Roles = roles.ToList()
                    });
                }

                response.Result = userDtos;
                response.isSuccess = true;
                response.Message = "User list retrieved";
                return Ok(response);
            }
            catch (Exception ex)
            {
                response.Message = $"Server error: {ex.InnerException?.Message ?? ex.Message}";
                return StatusCode(500, response);
            }
        }

        /// <summary>
        /// Gets profile for a specific user.
        /// </summary>
        [HttpGet("users/{id}")]
        public async Task<IActionResult> GetUserById(string id)
        {
            var response = new ResponseDto();

            try
            {
                var user = await _userManager.FindByIdAsync(id);
                if (user == null)
                    return NotFound(new ResponseDto { Message = "User not found." });

                var roles = await _userManager.GetRolesAsync(user);

                var dto = new AppUserDto
                {
                    Id = user.Id,
                    UserName = user.UserName,
                    Email = user.Email,
                    DisplayName = user.DisplayName,
                    Roles = roles.ToList()
                };

                response.Result = dto;
                response.isSuccess = true;
                response.Message = "User retrieved";
                return Ok(response);
            }
            catch (Exception ex)
            {
                response.Message = $"Server error: {ex.InnerException?.Message ?? ex.Message}";
                return StatusCode(500, response);
            }
        }

        private List<string> GetRoles(ManageUserRoleDto dto)
        {
            List<string> rolesList = null;

            if (dto.Roles.Count() > 0)
            {
                rolesList = new List<string>();
                foreach (var r in dto.Roles)
                {
                    if (!Enum.TryParse<AppRole>(r, true, out var roleEnum))
                        throw new Exception("Invalid role specified.");

                    rolesList.Add(r);
                }
            }

            return rolesList;
        }
    }
}