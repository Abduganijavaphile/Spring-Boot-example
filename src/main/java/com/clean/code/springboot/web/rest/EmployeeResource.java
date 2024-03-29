package com.clean.code.springboot.web.rest;

import com.clean.code.springboot.domain.Employee;
import com.clean.code.springboot.security.SecurityUtils;
import com.clean.code.springboot.service.EmployeeService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/api")
public class EmployeeResource {
    private final EmployeeService employeeService;

    public EmployeeResource(EmployeeService employeeService) {
        this.employeeService = employeeService;
    }
    @PostMapping("/employees")
    public ResponseEntity create(@RequestBody Employee employee){
        Employee employee1 = employeeService.save(employee);
        return ResponseEntity.ok(employee1);
    }
    @PutMapping("/employees")
    public ResponseEntity update(@RequestBody Employee employee){
        Employee employee1 = employeeService.save(employee);
        return ResponseEntity.ok(employee1);
    }
    @GetMapping("/employees")
    public ResponseEntity getAll(){
        List<Employee> employeeList = employeeService.findAll();
        return ResponseEntity.ok(employeeList);
    }
    @GetMapping("/employees/{firstName}")
    public ResponseEntity getAll(@PathVariable String firstName){
        Optional<String> optional = SecurityUtils.getCurrentUserName();
        List<Employee> employeeList = employeeService.findByFirstName(firstName);
        return ResponseEntity.ok(employeeList);
    }
    @GetMapping("/employees/search")
    public ResponseEntity getAllSearch(@RequestParam String firstName){
        List<Employee> employeeList = employeeService.findAllByParam(firstName);
        return ResponseEntity.ok(employeeList);
    }
    @DeleteMapping("/employees/{id}")
    public ResponseEntity delete(@PathVariable Long id){
        employeeService.delete(id);
        return ResponseEntity.ok("It is deleted");
    }
}
